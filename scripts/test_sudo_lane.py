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
import sys
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

# sink/consumer defs the lane itself defines at top
# level (sudo_lane.py: _say, run_logged): the only
# top-level defs exempt from rebind-voiding. If the
# lane ever defines another sink, extend this
# alongside (the tripwire tests pin it).
_LANE_DEFINED_SINKS = ("_say", "run_logged")


def _store_root(target, fresh=None):
    # container root a subscript/attribute store lands
    # in (box for box["k"]/box.attr, None when the
    # target binds plain names instead), plus the
    # descent depth (subscript/attribute/call steps
    # from the target to the root). Descends through
    # getter chains (box.get("rows") is owned by box
    # — mutating through it mutates box), but not
    # through computed calls (get_box() has no
    # resolvable owner): those stay a documented miss.
    # A proven-fresh .copy() result (fresh predicate
    # holds for the receiver) owns nothing either —
    # but ONLY as the immediate container (a store
    # through box.copy() lands in the copy, while a
    # store through box.copy()["rows"] lands in a
    # dict shared with the original — copies are
    # shallow). A .copy() on an unproven receiver
    # still descends (fail-closed: a custom copy may
    # return owned storage).
    root = target
    first = True
    depth = 0
    while True:
        if isinstance(root, (ast.Subscript, ast.Attribute)):
            # the store's own key/attr step keeps the
            # immediate container: box.copy()["k"] lands
            # in the copy (exempt), while
            # box.copy()["rows"]["k"] lands in shared
            # storage (the second step descends).
            if root is not target:
                first = False
            root = root.value
            depth += 1
        elif isinstance(root, ast.Call) \
                and isinstance(root.func, ast.Attribute):
            if first and fresh is not None \
                    and root.func.attr == "copy" \
                    and not root.args and not root.keywords \
                    and fresh(root.func.value):
                return None, depth
            root = root.func.value
            first = False
            depth += 1
        elif isinstance(root, ast.NamedExpr):
            # a walrus receiver IS its value (and binds it
            # too — the bind event joins the alias): unwrap
            # without a container step, keeping `first` so
            # (x := box.copy())["k"] still sees the fresh
            # copy as the immediate container.
            root = root.value
        else:
            break
    if isinstance(root, ast.Name):
        return root.id, depth
    return None, depth


def _unwrap_walrus(value):
    # assignments evaluate named expressions before
    # binding targets, so a target paired with one
    # binds the walrus VALUE (a = (t := v) binds a
    # to v, and t too): unwrap to it.
    while isinstance(value, ast.NamedExpr):
        value = value.value
    return value


def _provable_divzero(node):
    # a constant division/modulo by zero (any
    # constant numerator — numerics raise
    # ZeroDivisionError, the rest TypeError).
    return isinstance(node, ast.BinOp) \
        and isinstance(
            node.op, (ast.Div, ast.Mod, ast.FloorDiv)) \
        and isinstance(node.left, ast.Constant) \
        and isinstance(node.right, ast.Constant) \
        and node.right.value == 0


def _uncond_raises_expr(node):
    # True when evaluating node unconditionally
    # raises (a constant division/modulo by zero
    # outside conditional or deferred contexts:
    # IfExp arms, BoolOp/Compare tails, lambda
    # bodies, and comprehension interiors past
    # the first iterable never count — only the
    # parts that always evaluate do).
    if _provable_divzero(node):
        return True
    if isinstance(node, ast.BoolOp):
        return bool(node.values) \
            and _uncond_raises_expr(node.values[0])
    if isinstance(node, ast.IfExp):
        return _uncond_raises_expr(node.test)
    if isinstance(node, ast.Compare):
        return _uncond_raises_expr(node.left)
    if isinstance(node, ast.Lambda):
        return any(_uncond_raises_expr(default)
                   for default in
                   list(node.args.defaults)
                   + [default
                      for default in
                      node.args.kw_defaults
                      if default is not None])
    if isinstance(node, (ast.ListComp, ast.SetComp,
                         ast.DictComp, ast.GeneratorExp)):
        gens = node.generators
        return bool(gens) \
            and _uncond_raises_expr(gens[0].iter)
    return any(_uncond_raises_expr(child)
               for child in ast.iter_child_nodes(node)
               if isinstance(child, ast.expr))


def _simple_stmt_raises(stmt):
    # True when a simple statement unconditionally
    # raises during its own evaluation (constant
    # division by zero in an always-evaluated
    # operand — targets included).
    if isinstance(stmt, ast.Expr):
        parts = [stmt.value]
    elif isinstance(stmt, ast.Assign):
        parts = [stmt.value] + list(stmt.targets)
    elif isinstance(stmt, ast.AnnAssign):
        parts = [part for part in
                 (stmt.value, stmt.target,
                  stmt.annotation)
                 if part is not None]
    elif isinstance(stmt, ast.AugAssign):
        parts = [stmt.target, stmt.value]
    elif isinstance(stmt, ast.Delete):
        parts = list(stmt.targets)
    elif isinstance(stmt, ast.Return):
        parts = [stmt.value] \
            if stmt.value is not None else []
    else:
        return False
    return any(_uncond_raises_expr(part)
               for part in parts)


def _stmt_may_fall(stmt, soft_raise):
    # True when stmt may complete normally (fall
    # through to what follows it). Direct
    # return/break/continue never fall; raise and
    # assert fall only under soft_raise (kept
    # exits at top level); a provable constant
    # raise never falls. Compound predecessors
    # count when they definitely exit:
    # constant-folded or both-arms ifs, trys
    # whose body and handlers all exit (or whose
    # finally does), with-bodies exiting by
    # non-raise means (a raise may be suppressed
    # by __exit__). Loops, match, and nested
    # scopes stay opaque (an inner break binds
    # the inner loop; a nested return leaves the
    # block).
    if isinstance(stmt, (ast.Return, ast.Break,
                         ast.Continue)):
        return False
    if isinstance(stmt, (ast.Raise, ast.Assert)):
        return soft_raise
    if _simple_stmt_raises(stmt):
        return False
    if isinstance(stmt, ast.If):
        if _uncond_raises_expr(stmt.test):
            return False
        test = _unwrap_walrus(stmt.test)
        if isinstance(test, ast.Constant):
            if test.value is True:
                return _seq_may_fall(stmt.body,
                                     soft_raise)
            if test.value is False:
                return _seq_may_fall(stmt.orelse,
                                     soft_raise)
        return _seq_may_fall(stmt.body, soft_raise) \
            or _seq_may_fall(stmt.orelse, soft_raise)
    try_nodes = (ast.Try,)
    trystar = getattr(ast, "TryStar", None)
    if trystar is not None:
        try_nodes += (trystar,)
    if isinstance(stmt, try_nodes):
        if not _seq_may_fall(stmt.finalbody,
                             soft_raise):
            return False
        normal = not _seq_may_fall(stmt.body,
                                   soft_raise) \
            or (stmt.orelse
                and not _seq_may_fall(stmt.orelse,
                                      soft_raise))
        if not normal:
            return True
        return any(_seq_may_fall(handler.body,
                                 soft_raise)
                   for handler in stmt.handlers)
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return _seq_may_fall(stmt.body, True)
    return True


def _seq_may_fall(seq, soft_raise):
    return all(_stmt_may_fall(sub, soft_raise)
               for sub in seq)


def _stmts_quiet(stmts):
    # statements provably raising nothing: pass,
    # constant expressions, and constant binds to
    # bare names (anything else — calls,
    # subscripts, deletes, raises, control flow —
    # may raise; fail closed).
    for stmt in stmts:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) \
                and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Assign) \
                and isinstance(stmt.value, ast.Constant) \
                and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0],
                               ast.Name) \
                and isinstance(stmt.targets[0].ctx,
                               ast.Store):
            continue
        return False
    return True


def _scope_surfaces(tree, parents):
    # per-scope (imports, bound, globals, nonlocals)
    # for import-alias resolution: {scope id:
    # ({name: [root modules]}, {name: bind count},
    # {global names}, {nonlocal names})}. import x as y
    # binds the MODULE (from-imports bind objects —
    # skipped); an alias counts only with exactly one
    # bind (the import) in its own scope.
    # Self-contained pruned walks (runs before the
    # scope maps exist): nested scopes skipped whole,
    # so a walrus in nested kept parts is missed for
    # voiding (harmless verdicts on dead shapes only —
    # the name is rebound away from the module there).
    surfaces = {}
    scopes = [tree] + [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef,
                             ast.AsyncFunctionDef,
                             ast.Lambda, ast.ClassDef))]
    for scope in scopes:
        own_skip = set()
        if isinstance(scope, (ast.FunctionDef,
                              ast.AsyncFunctionDef)):
            parts = list(scope.decorator_list)
            parts.extend(scope.args.defaults)
            parts.extend(default for default in
                         scope.args.kw_defaults
                         if default is not None)
            for param in list(scope.args.args) \
                    + list(scope.args.kwonlyargs) \
                    + list(getattr(scope.args, "posonlyargs",
                                   [])):
                if param.annotation is not None:
                    parts.append(param.annotation)
            for extra in (scope.args.vararg,
                          scope.args.kwarg):
                if extra is not None \
                        and extra.annotation is not None:
                    parts.append(extra.annotation)
            if scope.returns is not None:
                parts.append(scope.returns)
        elif isinstance(scope, ast.Lambda):
            parts = list(scope.args.defaults)
            parts.extend(default for default in
                         scope.args.kw_defaults
                         if default is not None)
        elif isinstance(scope, ast.ClassDef):
            parts = list(scope.decorator_list)
            parts.extend(scope.bases)
            parts.extend(keyword.value
                         for keyword in scope.keywords)
        else:
            parts = []
        for part in parts:
            for sub in ast.walk(part):
                own_skip.add(id(sub))
        imports, bound, globs, nonlocs = {}, {}, set(), set()

        def count(name):
            bound[name] = bound.get(name, 0) + 1

        stack = [scope]
        while stack:
            node = stack.pop()
            if id(node) in own_skip:
                continue
            if node is not scope and isinstance(
                    node, (ast.FunctionDef,
                           ast.AsyncFunctionDef,
                           ast.Lambda, ast.ClassDef)):
                if not isinstance(node, ast.Lambda):
                    count(node.name)
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname is not None:
                        imports.setdefault(
                            alias.asname, []).append(
                                alias.name.split(".")[0])
                        count(alias.asname)
            if isinstance(node, ast.Name) \
                    and isinstance(node.ctx, ast.Store):
                count(node.id)
            if isinstance(node, (ast.FunctionDef,
                                 ast.AsyncFunctionDef,
                                 ast.Lambda)):
                for param in list(node.args.args) \
                        + list(node.args.kwonlyargs) \
                        + list(getattr(node.args,
                                       "posonlyargs", [])):
                    count(param.arg)
                for extra in (node.args.vararg,
                              node.args.kwarg):
                    if extra is not None:
                        count(extra.arg)
            if isinstance(node, ast.Match):
                for case in node.cases:
                    for name in _match_names(case.pattern):
                        count(name)
            if isinstance(node, ast.Global):
                globs.update(node.names)
            elif isinstance(node, ast.Nonlocal):
                nonlocs.update(node.names)
            stack.extend(ast.iter_child_nodes(node))
        surfaces[id(scope)] = (imports, bound, globs,
                               nonlocs)
    return surfaces


def _prologue_child(scope, child):
    # True when child sits in scope's enclosing-
    # evaluated prologue: decorators, defaults,
    # annotations, returns (functions), defaults
    # (lambdas), decorators/bases/keywords (classes).
    # A use there evaluates in the ENCLOSING scope —
    # the scope's own binds must not decide it. (A use
    # under a function's `arguments` node is always in
    # a default or annotation: parameter names bind,
    # they never read.)
    if isinstance(scope, (ast.FunctionDef,
                          ast.AsyncFunctionDef)):
        return child is scope.args \
            or child in scope.decorator_list \
            or child is scope.returns
    if isinstance(scope, ast.Lambda):
        return child is scope.args
    if isinstance(scope, ast.ClassDef):
        return child in scope.decorator_list \
            or child in scope.bases \
            or child in scope.keywords
    return False


def _surface_alias_at(surfaces, parents, node, name):
    # root module when name resolves to an unrebound
    # import alias at node (lexical: innermost
    # binding scope decides, global jumps to the
    # module, nonlocal to the nearest enclosing
    # function binding it, classes transparent
    # except directly enclosing); else None.
    chain = []
    current = node
    first = True
    while id(current) in parents:
        child = current
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef,
                                ast.AsyncFunctionDef,
                                ast.Lambda)):
            if _prologue_child(current, child):
                continue
            chain.append(current)
            first = False
        elif isinstance(current, ast.ClassDef):
            if _prologue_child(current, child):
                continue
            if first:
                chain.append(current)
            first = False
    def single_import(scope_id):
        imports, bound, _gl, _nl = surfaces[scope_id]
        if bound.get(name, 0) != 1:
            return None
        mods = imports.get(name, [])
        if len(mods) == 1:
            return mods[0]
        return None

    chain.append(current)
    root = current
    index = 0
    while index < len(chain):
        scope = chain[index]
        _imports, bound, globs, nonlocs = surfaces[
            id(scope)]
        if name in globs:
            return single_import(id(root))
        if name in nonlocs:
            for outer in chain[index + 1:]:
                if isinstance(outer, (ast.FunctionDef,
                                      ast.AsyncFunctionDef)) \
                        and name in surfaces[
                            id(outer)][1]:
                    return single_import(id(outer))
            return None
        if name in bound:
            return single_import(id(scope))
        index += 1
    return None


def _module_alias_root(surfaces, parents, scope_binds, node, name):
    # the import module `name` denotes at `node`,
    # following preserved `alias = <Name>` chains
    # (destructured pairs included — their values
    # are the paired names; self-assigns skipped,
    # they preserve) through the lexical scope walk
    # (global/nonlocal honored, classes transparent
    # except directly enclosing). None when
    # unresolvable, rebound, or cyclic. Each link
    # resolves as-of the site (binds strictly
    # before it; the last one wins — a stale
    # over-read fails closed at the callers).
    chain = []
    current = node
    first = True
    while id(current) in parents:
        child = current
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef,
                                ast.AsyncFunctionDef,
                                ast.Lambda)):
            if _prologue_child(current, child):
                continue
            chain.append(current)
            first = False
        elif isinstance(current, ast.ClassDef):
            if _prologue_child(current, child):
                continue
            if first:
                chain.append(current)
            first = False
    chain.append(current)
    root = current
    sitepos = (node.lineno, node.col_offset)
    seen = set()
    while name not in seen:
        seen.add(name)
        scope = None
        index = 0
        while index < len(chain):
            cand = chain[index]
            _imports, bound, globs, nonlocs = surfaces[
                id(cand)]
            if name in globs:
                scope = root
                break
            if name in nonlocs:
                for outer in chain[index + 1:]:
                    if isinstance(
                            outer,
                            (ast.FunctionDef,
                             ast.AsyncFunctionDef)) \
                            and name in surfaces[
                                id(outer)][1]:
                        scope = outer
                        break
                break
            if name in bound:
                scope = cand
                break
            index += 1
        if scope is None:
            return None
        imports = surfaces[id(scope)][0]
        target = None
        for _bpos, bkind, bval in reversed(
                scope_binds.get(id(scope), {}).get(
                    name, [])):
            if _bpos >= sitepos:
                continue
            if bkind == "plain" and isinstance(
                    _unwrap_walrus(bval), ast.Name):
                rhs = _unwrap_walrus(bval).id
                if rhs == name:
                    continue
                target = rhs
                break
            if bval is None and name in imports \
                    and len(imports[name]) == 1:
                return imports[name][0]
            return None
        if target is None:
            return None
        name = target
    return None


def _copy_source_names(value, trusted_builtin):
    # names whose descendants a shallow copy shares:
    # no-arg .copy() (any receiver — a custom copy
    # returning fresh over-taints, fail-closed),
    # single-arg dict()/list()/set() on trusted
    # builtins, single-source {**x} — recovered
    # RECURSIVELY through compositions (box.copy().
    # copy(), dict(box.copy()), {**{**box}} all share
    # the innermost source's descendants; recursion
    # descends strict subterms, so it terminates).
    # A walrus receiver or operand resolves to its
    # value ((a := box).copy() shares box — the
    # walrus bind itself is a separate event; a
    # copy-valued walrus recurses to the inner
    # source).
    # Multi-source unpacking and anything else yield
    # () (unknown shapes stay kills: {**a, **b}
    # sharing is a documented miss).
    if isinstance(value, ast.NamedExpr):
        if isinstance(value.value, ast.Name):
            return (value.value.id,)
        return _copy_source_names(value.value,
                                  trusted_builtin)
    if isinstance(value, ast.Call):
        if isinstance(value.func, ast.Attribute) \
                and value.func.attr == "copy" \
                and not value.args and not value.keywords:
            receiver = value.func.value
            if isinstance(receiver, ast.Name):
                return (receiver.id,)
            return _copy_source_names(
                receiver, trusted_builtin)
        if isinstance(value.func, ast.Name) \
                and len(value.args) == 1 \
                and not value.keywords \
                and trusted_builtin(value.func.id):
            arg = value.args[0]
            if isinstance(arg, ast.Name):
                return (arg.id,)
            return _copy_source_names(arg, trusted_builtin)
        return ()
    if isinstance(value, ast.Dict):
        unpacked = [item for key, item in
                    zip(value.keys, value.values)
                    if key is None]
        if len(unpacked) == 1:
            sole = unpacked[0]
            if isinstance(sole, ast.Name):
                return (sole.id,)
            return _copy_source_names(sole, trusted_builtin)
    return ()


def _pair_layers(node):
    # [(key, value)] for a literal pair iterable
    # (a list/tuple display of 2-sequences), else
    # None. Sets of pairs are unusable moot (dict
    # values are unhashable carriers) and names
    # stay mapping-interpreted (pairs-ambiguity
    # documented) — neither normalizes here.
    node = _unwrap_walrus(node)
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    pairs = []
    for elt in node.elts:
        elt = _unwrap_walrus(elt)
        if not isinstance(elt, (ast.List, ast.Tuple)) \
                or len(elt.elts) != 2:
            return None
        pairs.append((elt.elts[0], elt.elts[1]))
    return pairs


def _copy_display_operand(value, trusted_builtin):
    # the display operand of a copy-form call sharing its
    # values/elements (shallow), or None: x.copy() over a
    # dict/list/tuple/set display, dict() over a dict
    # display (plus dict-with-keywords, merged below),
    # list()/set() over a list/tuple/set display
    # (trusted ctors only, mirroring _copy_source_names).
    # Mismatched pairs (list() over a dict yields keys,
    # not values) are not copies. Inner copy-forms
    # resolve before the constructor validates, so
    # nested compositions (d.copy().copy(),
    # dict(d.copy()), list(list(xs)), dict(dict(d)))
    # route the innermost display.
    value = _unwrap_walrus(value)
    if not isinstance(value, ast.Call):
        return None
    operand = None
    if isinstance(value.func, ast.Attribute):
        if value.func.attr != "copy" or value.args \
                or value.keywords:
            return None
        operand = _unwrap_walrus(value.func.value)
    elif isinstance(value.func, ast.Name) \
            and trusted_builtin(value.func.id):
        if value.func.id == "dict":
            if len(value.args) > 1:
                return None
            positional = _unwrap_walrus(value.args[0]) \
                if len(value.args) == 1 else None
            presolved = None
            if positional is not None:
                presolved = _copy_display_operand(
                    positional, trusted_builtin)
            pretarget = presolved \
                if presolved is not None else positional
            if value.keywords or (
                    pretarget is not None
                    and _pair_layers(pretarget)
                    is not None):
                # dict(x?, **kw) / dict(<pairs>): one
                # structural display merging layers in
                # update order — the positional (a
                # display flattened, an inner copy-form
                # resolved, a pair iterable as explicit
                # entries, anything else unpacked) with
                # each **mapping (same treatment) and
                # each k=v explicit. Later known keys
                # overwrite earlier ones; unknown keys
                # and unpacks stay conservative.
                # Flattening is depth-neutral (unpacks
                # cost 0, explicits cost 1 either way).
                layers = []

                def _merge(target):
                    if isinstance(target, ast.Dict):
                        layers.extend(
                            zip(target.keys, target.values))
                        return
                    pairs = _pair_layers(target)
                    if pairs is not None:
                        layers.extend(pairs)
                        return
                    layers.append((None, target))

                if positional is not None:
                    _merge(pretarget)
                for keyword in value.keywords:
                    kval = _unwrap_walrus(keyword.value)
                    if keyword.arg is None:
                        resolved = _copy_display_operand(
                            kval, trusted_builtin)
                        _merge(resolved
                               if resolved is not None
                               else kval)
                    else:
                        key = ast.Constant(
                            value=keyword.arg)
                        ast.copy_location(key,
                                          keyword.value)
                        layers.append((key, kval))
                survivors = []
                dropped_keys = []
                for key, val in reversed(layers):
                    if isinstance(key, ast.Constant):
                        # later known keys overwrite
                        # earlier ones by dict-key
                        # equality (0 and False are one
                        # key; NaN never equals, like
                        # the dict itself).
                        if any(key.value == seen
                               for seen in dropped_keys):
                            continue
                        dropped_keys.append(key.value)
                    survivors.append((key, val))
                survivors.reverse()
                synth = ast.Dict(
                    keys=[key for key, _ in survivors],
                    values=[val for _, val in survivors])
                ast.copy_location(synth, value)
                return synth
            if len(value.args) != 1:
                return None
            operand = _unwrap_walrus(value.args[0])
            resolved = _copy_display_operand(
                operand, trusted_builtin)
            if resolved is not None:
                operand = resolved
            if not isinstance(operand, ast.Dict):
                return None
        elif value.func.id in ("list", "set") \
                and not value.keywords \
                and len(value.args) == 1:
            operand = _unwrap_walrus(value.args[0])
            resolved = _copy_display_operand(
                operand, trusted_builtin)
            if resolved is not None:
                operand = resolved
            if not isinstance(operand, (ast.List, ast.Tuple,
                                        ast.Set)):
                return None
        else:
            return None
    else:
        return None
    inner = _copy_display_operand(operand, trusted_builtin)
    if inner is not None:
        return inner
    if isinstance(operand, (ast.Dict, ast.List, ast.Tuple,
                            ast.Set)):
        return operand
    return None


def _pure_binder(target):
    # a comprehension target binding bare names
    # only (no Subscript/Attribute: those
    # evaluate their containers; a Starred
    # binder holds a fresh list).
    if isinstance(target, ast.Name):
        return True
    if isinstance(target, ast.Starred):
        return _pure_binder(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return all(_pure_binder(elt)
                   for elt in target.elts)
    return False


def _load_free(value, trusted_builtin):
    # a value built from pure literal structure:
    # nested displays, pure tuples, constants,
    # no-arg trusted ctors (at any depth — a
    # nested dict() is fresh wherever it sits),
    # comprehension binders with load-free
    # iters/conditions/elements, and walrus
    # values (the target is a bare Name by
    # grammar; the rebind is tracked as its own
    # bind). A load may retain the old object or
    # its descendants, so anything unrecognized
    # — names, attributes, subscripts, other
    # calls, operators, conditionals, lambdas —
    # fails closed.
    if isinstance(value, ast.Constant):
        return True
    if isinstance(value, ast.Dict):
        for key, val in zip(value.keys, value.values):
            if key is None:
                if not _load_free(val, trusted_builtin):
                    return False
            elif not _load_free(key, trusted_builtin) \
                    or not _load_free(val, trusted_builtin):
                return False
        return True
    if isinstance(value, (ast.List, ast.Set, ast.Tuple)):
        return all(_load_free(elt, trusted_builtin)
                   for elt in value.elts)
    if isinstance(value, ast.Starred):
        return _load_free(value.value, trusted_builtin)
    if isinstance(value, ast.NamedExpr):
        return _load_free(value.value, trusted_builtin)
    if isinstance(value, (ast.ListComp, ast.SetComp,
                           ast.DictComp, ast.GeneratorExp)):
        if isinstance(value, ast.DictComp):
            parts = [value.key, value.value]
        else:
            parts = [value.elt]
        if not all(_load_free(part, trusted_builtin)
                   for part in parts):
            return False
        return all(
            _pure_binder(gen.target)
            and _load_free(gen.iter, trusted_builtin)
            and all(_load_free(cond, trusted_builtin)
                    for cond in gen.ifs)
            for gen in value.generators)
    if isinstance(value, ast.Call):
        return isinstance(value.func, ast.Name) \
            and not value.args and not value.keywords \
            and trusted_builtin(value.func.id)
    return False


def _fresh_value(value, trusted_builtin):
    # values that provably denote a new object
    # disconnected from the old one: load-free
    # structure (displays, pure tuples,
    # constants, no-arg trusted ctors,
    # load-free comprehensions — any load may
    # retain a reference, so displays with loads
    # stay unknown kills, fail-closed).
    # Everything else — names, subscripts,
    # attributes, other calls, operators
    # (overloading may return an operand),
    # conditionals (may select the old object),
    # lambdas — stays an unknown kill: the old
    # object may flow back, so the edge
    # survives (fail-closed).
    return _load_free(value, trusted_builtin)


def _target_leaves(target):
    # every leaf a binding target touches, recursing
    # tuples/lists/starred: namespace stores and
    # attribute binds hide inside destructuring
    # (globals()["a"], x = ...).
    if isinstance(target, ast.Starred):
        yield from _target_leaves(target.value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _target_leaves(elt)
    else:
        yield target


def _class_annotated(home):
    # a direct class-body annotation of a bare name
    # (nested scopes pruned — their annotations are
    # their own): only these install __annotations__
    # on the pre-3.14 eager path.
    stack = list(home.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef,
                             ast.AsyncFunctionDef,
                             ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.AnnAssign) \
                and isinstance(node.target, ast.Name):
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _splat_elts(elts):
    # statically expand Starred-over-literal (recursively);
    # None when any element's width is unknowable (a dynamic
    # splat — callers fall back to whole-value pairing).
    out = []
    for elt in elts:
        if isinstance(elt, ast.Starred):
            inner = elt.value
            if not isinstance(inner, (ast.Tuple, ast.List)):
                return None
            sub = _splat_elts(inner.elts)
            if sub is None:
                return None
            out.extend(sub)
        else:
            out.append(elt)
    return out


def _walk_pairs(target, value):
    # (leaf-target, corresponding-value) pairs for a
    # destructured assignment; uneven shapes pair each
    # leaf with the whole value (fail-closed: the
    # value is judged, not skipped — and no leaf
    # hides inside the unvisited target). Static RHS
    # stars expand before pairing (a, b = *[box], {}
    # pairs a with box). Around one starred target,
    # known prefixes and suffixes pair positionally
    # and the star consumes the middle (possibly
    # empty) with element provenance as one Tuple
    # of the consumed values; a lone starred target
    # binds a FRESH
    # list, so it pairs with the Starred node
    # itself (a non-Name, non-copy value — callers
    # kill it) instead of the operand's object.
    # Starred namespace targets (*c.x) lose element
    # provenance (callers kill namespace pairs —
    # documented miss).
    if isinstance(target, ast.Starred):
        yield target.value, target
        return
    if isinstance(target, (ast.Tuple, ast.List)) \
            and isinstance(value, (ast.Tuple, ast.List)):
        expanded = _splat_elts(value.elts)
        if expanded is not None:
            stars = [index for index, elt
                     in enumerate(target.elts)
                     if isinstance(elt, ast.Starred)]
            if not stars \
                    and len(expanded) == len(target.elts):
                for sub_target, sub_value in zip(
                        target.elts, expanded):
                    yield from _walk_pairs(sub_target,
                                           sub_value)
                return
            if len(stars) == 1:
                at = stars[0]
                pre = target.elts[:at]
                suf = target.elts[at + 1:]
                if len(expanded) >= len(pre) + len(suf):
                    # target order (the star binds
                    # between its prefix and suffix):
                    # same-batch same-name replays
                    # last-target-wins.
                    for sub_target, sub_value in zip(
                            pre, expanded):
                        yield from _walk_pairs(sub_target,
                                               sub_value)
                    middle = expanded[len(pre):len(
                        expanded) - len(suf)] if suf \
                        else expanded[len(pre):]
                    inner = target.elts[at].value
                    if middle:
                        # element provenance rides one
                        # parentless Tuple of the
                        # consumed values (resolved by
                        # the star-aware store path;
                        # callers otherwise kill it —
                        # real tuples stay in the
                        # parents map, so they never
                        # resolve).
                        synth = ast.Tuple(
                            elts=list(middle),
                            ctx=ast.Load())
                        ast.copy_location(
                            synth, target.elts[at])
                        yield inner, synth
                    else:
                        yield inner, target.elts[at]
                    if suf:
                        for sub_target, sub_value in zip(
                                suf, expanded[len(
                                    expanded) - len(suf):]):
                            yield from _walk_pairs(
                                sub_target, sub_value)
                    return
    if isinstance(target, (ast.Tuple, ast.List)):
        for leaf in _target_leaves(target):
            yield leaf, value
    else:
        yield target, value


_NAMESPACE_MUTATORS = ("update", "setdefault", "__setitem__", "__ior__")


# Pure path/string combinators whose result embeds
# their arguments: taint spreads through these (and
# only these) when their arguments carry it. NOT
# every call: verdicts, counts, partials and child
# bytes abstract their tainted inputs rather than
# carrying the path, and spreading through them
# drowns the audit (29 self-audit violations on the
# real file, first-hand). Custom path wrappers
# outside this list are a documented miss (see the
# known-narrow list): this guard catches mechanical
# reverts, not novel exfil primitives.
_PATH_BUILDERS = frozenset({
    "str", "join", "joinpath", "fspath", "format",
    "dirname", "basename", "normpath", "abspath",
    "realpath", "relpath", "expanduser", "expandvars",
    "fsdecode", "fsencode", "normcase", "split",
})


def _call_simple_name(func):
    # the unqualified callee name (join for
    # os.path.join and "/".join alike; None for
    # computed callees, which are unknown sinks).
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _binding_violations(source):
    """Tripwire violations for `source` (taint over execute/prepare).

    No reads through the log path or its aliases: taint seeds
    from the `log` name and from each run_logged call's log
    argument (a renamed seed must not launder it), flows
    through every rebinding form (assign, for, walrus, match;
    with/except names rebind but carry __enter__/exception
    values, never the path) and through targeted value
    shapes (IfExp, BoolOp, BinOp, Subscript, f-string,
    attribute access, method calls on a tainted
    receiver, and path-builder calls — str/join/... —
    with tainted arguments), and must not reach a read
    or exec primitive — directly as a bare argument
    (starred arguments unwrapped) to any call except
    the diagnostic sinks (print, _say) and the bare
    run_logged consumer, both voided when rebound
    anywhere, by any form (plain, globals()/
    __builtins__/setattr/namespace-mutator incl.
    aliases, unbound, in-place-or and dunder
    forms, or dynamic — a
    dynamic namespace rebind, or a namespace object
    handed to an arbitrary callee, fails closed
    outright; a dotted .run_logged call is never
    the consumer; the sinks also void on an
    attribute bind of their name, the consumer on
    a builtins-rooted one, and any attribute bind
    through a computed root voids the bare name
    outright), and a call through a
    rebound method (Path.run_logged =
    Path.read_bytes, destructured binds, loop/with
    targets, attribute AugAssign, and plain-name-
    held scoped capabilities included) fires on
    a tainted receiver; a computed read reference
    (getattr/__dict__/...) fails closed as a read
    capability; and
    except the results.append publish sink narrowed
    to a CLEAN dict display or a CLEAN dict-bound-
    only name — dict targets must be direct Names
    (unpacking yields keys), mutations and nested
    def/class/global bindings void, tainted stores
    (subscript, attribute, or known-mutating method,
    receivers climbed through nesting and getter
    calls to the root — but never through a
    proven-fresh .copy() result as the immediate
    container) taint the container root, and data
    positions must carry no taint (a bare path, raw,
    keyed, or read back through a subscript, fires
    right at the append; dict keys count, and only
    str(x.relative_to(...)) — with str unrebound
    and un-attribute-bound and relative_to neither
    attribute-bound nor rebound (a method def voids
    it) — survives in a call position, as does a
    bare name proven to hold that string (copy
    components with a seed and no kills — a kill
    anywhere voids every use, a seeded cycle
    resolves, a lone self-copy stays out);
    recombining it (out/tag) rebuilds the raw path
    and fires);
    or
    nested inside a larger argument to a read/exec
    primitive (copy/getoutput shapes included, so
    derived-path bookkeeping through publish sinks
    stays allowed but laundered reads fire).
    Bare-name copies form alias groups
    (position-ordered events with pair-order
    sequences, rebinding detaches first so a
    retarget never merges objects, same-statement
    copies read the pre-statement groups with
    up-front RHS snapshots and shared pre-batch
    identities, any other binding kills membership
    except AugAssign, which may mutate in place,
    all scope-pruned so nested binds never leak):
    a store taints and voids the groups its name
    holds from just before its statement through
    the enclosing loop (unbounded in nested
    functions), so a store through one alias voids
    the peers it may actually share with.
    Containers
    (Tuple/List/Dict/Set displays)
    propagate taint, so a container round-trip back
    into a read fires; calls with an unrecognized
    callee (a call, a subscript, any other computed
    shape) are unknown sinks (a bare tainted argument
    fires), and read methods on tainted-containing
    receivers fire. Every run_logged is 3-unpacked
    (a discarded bare call is a violation too) with the
    bytes used past the call site but before the next
    rebinding of that name — namespace-mutator binds
    narrow the horizon too; positions are (line, col)
    so same-line semicolon rebinds narrow the horizon —
    and the deleted reader is gone module-wide.
    """
    read_attrs = ("open", "read_text", "read_bytes", "read")
    consumers = ("run_logged",)
    diagnostic_sinks = ("print", "_say")
    nested_denied = ("open", "Path", "PurePath", "PosixPath",
                     "PurePosixPath", "WindowsPath",
                     "PureWindowsPath", "fspath",
                     "check_output", "check_call", "run",
                     "Popen", "execv", "execve", "execl",
                     "execlp", "execvp", "execvpe", "system",
                     "popen", "read_bytes", "read_text",
                     "getoutput", "getstatusoutput",
                     "copyfile", "copy", "copy2", "move")
    tree = ast.parse(source)
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    surfaces = _scope_surfaces(tree, parents)
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
    module_attr_binds = set()
    builtins_attr_binds = set()
    # Unbound-dict trust starts tentative: the module
    # walk parses dict.update(ns, ...) precisely and
    # records each site; after the walk the final
    # rebound/attr sets decide, and untrusted sites
    # convert to dynamic (their tentative keys stay
    # in rebound — voiding exemptions is fail-closed).
    dict_trusted = True
    tentative_dict_unbound = []

    def read_ref(value, readcaps):
        # a read capability by shape alone (no taint
        # needed): a read-primitive name, a name
        # tracked as holding one, or a method
        # reference off one. Functions retrieved this
        # way bind their receiver when called through
        # an attribute, so the receiver's taint reads.
        if isinstance(value, ast.Name):
            return value.id in read_attrs \
                or value.id in readcaps
        if isinstance(value, ast.Attribute):
            return value.attr in read_attrs
        if isinstance(value, ast.Constant):
            # data, never a callable capability:
            # calling through it TypeErrors before it
            # can read anything.
            return False
        # computed (getattr(...) / __dict__[...] /
        # lambda / any other non-name shape):
        # unresolvable, fail closed — the bound
        # attribute is treated as a read capability.
        return True

    # (Readcap provenance lives below in
    # _cap_binds/_caps_from, after _namespace_store:
    # namespace-key binds join the per-scope maps.)

    def _namespace_expr(value):
        # a namespace object: a globals()/locals()/
        # vars() call (or a call through a name bound
        # to one of those bare functions), a name ever
        # bound to one (no kill — over-tracking a dead
        # alias only voids exemptions, never misses a
        # rebind), the bare __builtins__ name (a dict
        # under import — the lane runs imported), or a
        # __dict__ attribute of builtins/__builtins__
        # (import aliases included — import builtins as
        # b reaches the same dict; any other object's
        # __dict__ is that object's namespace, not the
        # module's — out of scope).
        if isinstance(value, ast.Call) \
                and isinstance(value.func, ast.Name) \
                and (value.func.id in _NAMESPACE_FUNCS
                     or value.func.id in ns_func_aliases):
            return True
        if isinstance(value, ast.Name):
            return value.id in ns_aliases \
                or value.id == "__builtins__"
        if not isinstance(value, ast.Attribute) \
                or value.attr != "__dict__":
            return False
        root = _store_root(value)[0]
        return root in ("builtins", "__builtins__") \
            or _surface_alias_at(
                surfaces, parents, value, root) == "builtins"

    ns_func_aliases = set()
    changed_func_alias = True
    while changed_func_alias:
        changed_func_alias = False
        for node in ast.walk(tree):
            pairs = []
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    pairs.extend(_walk_pairs(target, node.value))
            elif isinstance(node, ast.AnnAssign) \
                    and node.value is not None:
                pairs.extend(
                    _walk_pairs(node.target, node.value))
            elif isinstance(node, ast.NamedExpr):
                pairs.append((node.target, node.value))
            for target, value in pairs:
                if isinstance(target, ast.Name) \
                        and isinstance(value, ast.Name) \
                        and target.id not in ns_func_aliases \
                        and (value.id in _NAMESPACE_FUNCS
                             or value.id in ns_func_aliases):
                    ns_func_aliases.add(target.id)
                    changed_func_alias = True

    ns_aliases = set()
    changed_alias = True
    while changed_alias:
        changed_alias = False
        for node in ast.walk(tree):
            pairs = []
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    pairs.extend(_walk_pairs(target, node.value))
            elif isinstance(node, ast.AnnAssign) \
                    and node.value is not None:
                pairs.extend(
                    _walk_pairs(node.target, node.value))
            elif isinstance(node, ast.NamedExpr):
                pairs.append((node.target, node.value))
            for target, value in pairs:
                if isinstance(target, ast.Name) \
                        and target.id not in ns_aliases \
                        and _namespace_expr(value):
                    ns_aliases.add(target.id)
                    changed_alias = True

    ns_mutator_aliases = set()
    changed_mut_alias = True
    while changed_mut_alias:
        changed_mut_alias = False
        for node in ast.walk(tree):
            pairs = []
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    pairs.extend(_walk_pairs(target, node.value))
            elif isinstance(node, ast.AnnAssign) \
                    and node.value is not None:
                pairs.extend(
                    _walk_pairs(node.target, node.value))
            elif isinstance(node, ast.NamedExpr):
                pairs.append((node.target, node.value))
            for target, value in pairs:
                if not isinstance(target, ast.Name) \
                        or target.id in ns_mutator_aliases:
                    continue
                if isinstance(value, ast.Attribute) \
                        and value.attr in _NAMESPACE_MUTATORS \
                        and _namespace_expr(value.value):
                    ns_mutator_aliases.add(target.id)
                    changed_mut_alias = True
                elif isinstance(value, ast.Name) \
                        and value.id in ns_mutator_aliases:
                    ns_mutator_aliases.add(target.id)
                    changed_mut_alias = True

    def _namespace_store(target):
        # globals()["name"] = ... (locals/vars likewise,
        # or through a namespace alias) rebinds "name"
        # without an assignment-ish target. Returns
        # (found, key): key None means a dynamic
        # (non-constant) key — unresolvable, fail-closed
        # at the call site.
        if isinstance(target, ast.Subscript) \
                and _namespace_expr(target.value):
            key = target.slice
            if isinstance(key, ast.Constant) \
                    and isinstance(key.value, str):
                return True, key.value
            return True, None
        return False, None

    def _namespace_mutator_keys(node):
        # globals().update(_say=open) / .setdefault("k",
        # v) / .__setitem__("k", v) / .__ior__(...) rebind
        # names without an assignment target
        # (locals/vars likewise, or through a
        # namespace alias; unbound dict.update(ns, ...)
        # forms count with the namespace as the first
        # argument, but ONLY on the proven dict
        # builtin — any other receiver with a
        # namespace first argument is an arbitrary
        # method, resolved as dynamic by the caller).
        # Returns (is_mutator, keys, dynamic): keys
        # are the resolved constant names; dynamic
        # means a key is computed (fail-closed at the
        # call site).
        if not isinstance(node, ast.Call) \
                or not isinstance(node.func, ast.Attribute) \
                or node.func.attr not in _NAMESPACE_MUTATORS:
            return False, [], False
        args = node.args
        if _namespace_expr(node.func.value):
            pass
        elif args and _namespace_expr(args[0]) \
                and isinstance(node.func.value, ast.Name) \
                and node.func.value.id == "dict" \
                and dict_trusted:
            args = args[1:]
        else:
            return False, [], False
        keys, dynamic = [], False
        if node.func.attr in ("setdefault", "__setitem__"):
            if not args:
                return True, [], True
            key = args[0]
            if isinstance(key, ast.Constant) \
                    and isinstance(key.value, str):
                keys.append(key.value)
            else:
                dynamic = True
        else:
            for keyword in node.keywords:
                if keyword.arg is None:
                    dynamic = True
                else:
                    keys.append(keyword.arg)
            for arg in args:
                if isinstance(arg, ast.Dict):
                    for key in arg.keys:
                        if key is None:
                            dynamic = True
                        elif isinstance(key, ast.Constant) \
                                and isinstance(key.value, str):
                            keys.append(key.value)
                        else:
                            dynamic = True
                else:
                    dynamic = True
        return True, keys, dynamic

    def _namespace_ior_keys(node):
        # ns |= {...} on a proven namespace expression
        # (a namespace alias, the bare __builtins__
        # name, or builtins[-alias].__dict__ — the
        # in-place dict merge persists even when the
        # attribute re-store raises) rebinds keys
        # exactly like update. Any other target
        # mutates a value, not the namespace.
        # Returns the same triple as above.
        if not isinstance(node, ast.AugAssign) \
                or not isinstance(node.op, ast.BitOr) \
                or not _namespace_expr(node.target):
            return False, [], False
        keys, dynamic = [], False
        value = node.value
        if isinstance(value, ast.Dict):
            for key in value.keys:
                if key is None:
                    dynamic = True
                elif isinstance(key, ast.Constant) \
                        and isinstance(key.value, str):
                    keys.append(key.value)
                else:
                    dynamic = True
        else:
            dynamic = True
        return True, keys, dynamic

    def _passes_namespace(node):
        # a namespace object handed to an arbitrary
        # callee (evil(globals())): the callee could
        # stash or mutate it, so the call site fails
        # closed (a resolved mutator above takes
        # precedence — this is the unresolvable rest).
        return any(_namespace_expr(arg) for arg in node.args) \
            or any(_namespace_expr(keyword.value)
                   for keyword in node.keywords)

    def _builtins_attr(leaf):
        # an attribute bind through the builtins
        # module root (builtins.str = ... — import
        # aliases and preserved alias chains
        # included): the bare name every module
        # resolves is rebound.
        if not isinstance(leaf, ast.Attribute):
            return None
        root = _store_root(leaf)[0]
        if root == "builtins" \
                or _surface_alias_at(
                    surfaces, parents, leaf,
                    root) == "builtins" \
                or _module_alias_root(
                    surfaces, parents, scope_binds,
                    leaf, root) == "builtins":
            return leaf.attr
        return None

    def _kept_parts(node):
        # subtrees of a nested scope that evaluate in
        # the ENCLOSING scope (kept): decorators, bases,
        # defaults, annotations and returns. Bodies and
        # params are pruned (their binds are local);
        # lambda bodies prune whole (a walrus inside one
        # is lambda-local — only lambda defaults stay).
        # (3.14 defers annotations lazily, but no 3.14
        # program can bind through one — a walrus there
        # is a SyntaxError — so keeping them is exact on
        # 3.12 and harmless on 3.14.)
        roots = []
        if isinstance(node, (ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            roots.extend(node.decorator_list)
            roots.extend(node.args.defaults)
            roots.extend(default for default in
                         node.args.kw_defaults
                         if default is not None)
            for param in list(node.args.args) \
                    + list(node.args.kwonlyargs) \
                    + list(getattr(node.args, "posonlyargs",
                                   [])):
                if param.annotation is not None:
                    roots.append(param.annotation)
            for extra in (node.args.vararg, node.args.kwarg):
                if extra is not None \
                        and extra.annotation is not None:
                    roots.append(extra.annotation)
            if node.returns is not None:
                roots.append(node.returns)
        elif isinstance(node, ast.ClassDef):
            roots.extend(node.decorator_list)
            roots.extend(node.bases)
            roots.extend(keyword.value
                         for keyword in node.keywords)
        elif isinstance(node, ast.Lambda):
            roots.extend(node.args.defaults)
            roots.extend(default for default in
                         node.args.kw_defaults
                         if default is not None)
        keep = set()
        for kept in roots:
            for sub in ast.walk(kept):
                keep.add(id(sub))
        return keep

    def _scope_skip_ids(root):
        # ids of nested-scope bodies pruned from a
        # scope walk (shared by the binds and alias
        # walkers so both see the same scope).
        skip = set()
        for node in ast.walk(root):
            if node is not root and isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef,
                           ast.ClassDef, ast.Lambda)):
                keep = _kept_parts(node)
                for sub in ast.walk(node):
                    if sub is not node \
                            and id(sub) not in keep:
                        skip.add(id(sub))
        return skip

    def _scope_binds(root, params=()):
        # plain-name (+ namespace-key) bindings within
        # ONE scope: {name: [(pos, kind, value)]}. kind
        # is "plain" (an Assign/AnnAssign/NamedExpr
        # value, or None for a kill form), "for" (a
        # For-target bind with the ITER node as value)
        # or "def" (a nested def/class NAME with its
        # node as value). Nested def/class bodies never
        # leak in (their binds are local); their
        # decorators, bases and defaults DO evaluate in
        # this scope and are visited, as are lambda
        # defaults — only lambda bodies are pruned (a
        # walrus inside one is lambda-local). Params
        # bind here as kill forms (callers pass
        # anything). Comprehension targets are local
        # (kept in the comp_binds_by_name side table,
        # span-gated — a walrus inside one binds here
        # and is visited). Global/nonlocal
        # declarations bind here (imprecise:
        # documented).
        binds = {}

        def note(name, pos, kind, value):
            binds.setdefault(name, []).append(
                (pos, kind, value))

        def kill_leaf(target, pos):
            for leaf in _target_leaves(target):
                found, key = _namespace_store(leaf)
                if found and key is not None:
                    note(key, pos, "plain", None)
                else:
                    for name in _bound_names(leaf):
                        note(name, pos, "plain", None)

        skip = _scope_skip_ids(root)
        if isinstance(root, (ast.FunctionDef,
                             ast.AsyncFunctionDef,
                             ast.Lambda, ast.ClassDef)):
            # the root's own decorators, defaults,
            # bases and annotations evaluate in the
            # ENCLOSING scope — they bind there (noted
            # by the enclosing scope's own walk), never
            # here.
            skip = skip | _kept_parts(root)
        for node in ast.walk(root):
            if id(node) in skip:
                continue
            # the Module root itself carries no position
            # (it matches no arm below — harmless).
            pos = (getattr(node, "lineno", 0),
                   getattr(node, "col_offset", 0))
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if value is None:
                    continue
                targets = node.targets if isinstance(
                    node, ast.Assign) else [node.target]
                for target in targets:
                    for leaf, val in _walk_pairs(target,
                                                 value):
                        found, key = _namespace_store(leaf)
                        if found and key is not None:
                            note(key, pos, "plain", val)
                        else:
                            for name in _bound_names(leaf):
                                note(name, pos, "plain",
                                     _unwrap_walrus(val))
            elif isinstance(node, ast.NamedExpr):
                note(node.target.id, pos, "plain",
                     _unwrap_walrus(node.value))
            elif isinstance(node, ast.AugAssign):
                kill_leaf(node.target, pos)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                for leaf in _target_leaves(node.target):
                    found, key = _namespace_store(leaf)
                    if found and key is not None:
                        note(key, pos, "plain", None)
                    else:
                        for name in _bound_names(leaf):
                            note(name, pos, "for", node.iter)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        kill_leaf(item.optional_vars, pos)
            elif isinstance(node, ast.ExceptHandler):
                if node.name:
                    note(node.name, pos, "plain", None)
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    for name in _match_names(case.pattern):
                        note(name, pos, "plain", None)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    note(alias.asname
                         or alias.name.split(".")[0],
                         pos, "plain", None)
            elif isinstance(node, (ast.FunctionDef,
                                   ast.AsyncFunctionDef,
                                   ast.ClassDef)) \
                    and node is not root:
                note(node.name, pos, "def", node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for name in node.names:
                    note(name, pos, "plain", None)
        for param in params:
            note(param, (root.lineno, root.col_offset),
                 "plain", None)
        return binds

    def _def_harmless(node):
        # a nested def provably returning no reads: no
        # decorators, every return/yield a bare
        # Constant (or absent — implicit None). Anything
        # else may read when called: fail closed.
        if not isinstance(node, (ast.FunctionDef,
                                 ast.AsyncFunctionDef)) \
                or node.decorator_list:
            return False
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return):
                if sub.value is not None and not isinstance(
                        sub.value, ast.Constant):
                    return False
            elif isinstance(sub, (ast.Yield, ast.YieldFrom)):
                if not isinstance(sub, ast.Yield) \
                        or sub.value is not None \
                        and not isinstance(sub.value,
                                           ast.Constant):
                    return False
        return True

    def _scc_in(binds, classify, resolve_peer):
        # least fixpoint over strongly-connected copy
        # components (naive reachability — graphs are
        # tiny): IN(SCC) iff no member has an OUT bind,
        # every copy peer is IN, and the SCC is seeded
        # or has an IN peer outside it. Self-copies are
        # neutral (skipped by the classifier); unseeded
        # cycles and lone self-copies stay OUT; seeded
        # cycles resolve. classify(name, bind) returns
        # (out, peers, seed); resolve_peer(peer) returns
        # None for same-scope peers (decided here) or a
        # bool for externally resolved ones.
        info = {}
        for name, blist in binds.items():
            out = False
            peers = set()
            seed = False
            ext = {}
            for bind in blist:
                one_out, some_peers, one_seed = classify(
                    name, bind)
                out = out or one_out
                seed = seed or one_seed
                for peer in some_peers:
                    if peer == name:
                        continue
                    resolved = resolve_peer(peer)
                    if resolved is None:
                        peers.add(peer)
                    else:
                        ext[peer] = resolved
            info[name] = (out, peers, seed, ext)

        def reaches(start, goal, seen):
            if start == goal:
                return True
            for nxt in info[start][1]:
                if nxt not in seen \
                        and reaches(nxt, goal,
                                    seen | {nxt}):
                    return True
            return False

        sccs = []
        for name in binds:
            scc = frozenset(
                peer for peer in binds
                if reaches(name, peer, {name})
                and reaches(peer, name, {peer}))
            if scc not in sccs:
                sccs.append(scc)
        scc_of = {}
        for scc in sccs:
            for member in scc:
                scc_of[member] = scc
        inside = set()
        changed = True
        while changed:
            changed = False
            for scc in sccs:
                if scc in inside:
                    continue
                ok = True
                seeded = False
                ext_in = False
                for member in scc:
                    out, peers, seed, ext = info[member]
                    if out:
                        ok = False
                        break
                    seeded = seeded or seed
                    for peer in peers:
                        if scc_of[peer] is scc:
                            continue
                        if scc_of[peer] not in inside:
                            ok = False
                            break
                        ext_in = True
                    if not ok:
                        break
                    for _peer, resolved in ext.items():
                        if not resolved:
                            ok = False
                            break
                        ext_in = True
                    if not ok:
                        break
                if ok and (seeded or ext_in):
                    inside.add(scc)
                    changed = True
        return {name for scc in inside for name in scc}

    def _func_params(node):
        params = [param.arg
                  for param in list(node.args.args)
                  + list(node.args.kwonlyargs)
                  + list(getattr(node.args, "posonlyargs",
                                 []))]
        for extra in (node.args.vararg, node.args.kwarg):
            if extra is not None:
                params.append(extra.arg)
        return params

    module_scope_binds = _scope_binds(tree)
    scope_binds = {id(tree): module_scope_binds}
    for scope_node in ast.walk(tree):
        if isinstance(scope_node, (ast.FunctionDef,
                                   ast.AsyncFunctionDef,
                                   ast.Lambda)):
            scope_binds[id(scope_node)] = _scope_binds(
                scope_node, _func_params(scope_node))
        elif isinstance(scope_node, ast.ClassDef):
            # class bodies bind their own namespace
            # (methods, class attrs); bases and
            # decorators evaluate enclosing but are
            # walked here — a walrus inside one is
            # misattributed to the class (documented
            # narrow: pathological shapes only).
            scope_binds[id(scope_node)] = _scope_binds(
                scope_node)
    # comprehension loop variables are local to
    # their comprehension (never outward — they do
    # not leak) but decide uses inside it: a walrus
    # value in the element reads the comprehension
    # environment, not the outer scope. Kept in a
    # side table (never in scope_binds — other
    # consumers assume outward visibility) merged
    # only into the holds() candidate list; the
    # span gate in sees() scopes them (a use
    # outside the comprehension span, including
    # the outermost iterable's own reads, never
    # observes them — nesting and shadowing fall
    # out of span containment plus position
    # order).
    comp_binds_by_name = {}
    comp_spans = {}
    for comp_node in ast.walk(tree):
        if not isinstance(comp_node, (ast.ListComp, ast.SetComp,
                                      ast.DictComp,
                                      ast.GeneratorExp)):
            continue
        cspan = ((comp_node.lineno, comp_node.col_offset),
                 (comp_node.end_lineno,
                  comp_node.end_col_offset))
        for gen in comp_node.generators:
            comp_spans[id(gen.iter)] = (
                cspan, (gen.iter.lineno,
                        gen.iter.col_offset),
                (gen.iter.end_lineno,
                 gen.iter.end_col_offset))
            pos = (gen.target.lineno,
                   gen.target.col_offset)
            for leaf in _target_leaves(gen.target):
                found, key = _namespace_store(leaf)
                if found and key is not None:
                    comp_binds_by_name.setdefault(
                        key, []).append((pos, "plain",
                                        gen.iter))
                else:
                    for name in _bound_names(leaf):
                        comp_binds_by_name.setdefault(
                            name, []).append((pos, "for",
                                              gen.iter))
    scope_declared = {}
    for scope_node in ast.walk(tree):
        if scope_node is tree or isinstance(
                scope_node, (ast.FunctionDef,
                             ast.AsyncFunctionDef,
                             ast.Lambda, ast.ClassDef)):
            skip = _scope_skip_ids(scope_node)
            globs, nonlocs = set(), set()
            for node in ast.walk(scope_node):
                if id(node) in skip:
                    continue
                if isinstance(node, ast.Global):
                    globs.update(node.names)
                elif isinstance(node, ast.Nonlocal):
                    nonlocs.update(node.names)
            scope_declared[id(scope_node)] = (globs, nonlocs)
    def lexical_use_chain(node):
        # scopes deciding a USE, innermost first: the
        # enclosing functions/lambdas out to the
        # module, plus a directly-enclosing class body
        # (its names are visible to code directly
        # inside it — but transparent to deeper
        # functions, which never close over it). A use
        # in a scope's prologue (decorators, defaults,
        # annotations, bases) evaluates in the
        # ENCLOSING scope, so that scope is skipped.
        chain = []
        current = node
        first = True
        while id(current) in parents:
            child = current
            current = parents[id(current)]
            if isinstance(current, (ast.FunctionDef,
                                    ast.AsyncFunctionDef,
                                    ast.Lambda)):
                if _prologue_child(current, child):
                    continue
                chain.append(current)
                first = False
            elif isinstance(current, ast.ClassDef):
                if _prologue_child(current, child):
                    continue
                if first:
                    chain.append(current)
                first = False
            if current is tree:
                break
        if not chain or chain[-1] is not tree:
            chain.append(tree)
        return chain

    def lexical_binds(name, node):
        # the scope whose binds decide a use of name at
        # node: innermost scope binding it, honoring
        # global (jump to module) and nonlocal (jump to
        # the nearest enclosing function binding it —
        # lambdas cannot declare either, and no def can
        # nest inside a lambda body, so the target is
        # always a FunctionDef). Returns None when no
        # scope binds the name.
        chain = lexical_use_chain(node)
        index = 0
        while index < len(chain):
            scope = chain[index]
            globs, nonlocs = scope_declared.get(
                id(scope), (set(), set()))
            if name in globs:
                if name in scope_binds[id(tree)]:
                    return tree
                return None
            if name in nonlocs:
                for outer in chain[index + 1:]:
                    if isinstance(outer, (ast.FunctionDef,
                                          ast.AsyncFunctionDef)) \
                            and name in scope_binds[id(outer)]:
                        return outer
                return None
            if name in scope_binds.get(id(scope), {}):
                return scope
            index += 1
        return None

    def _fresh_copy_root(value):
        # the object a copy-chain bottoms out at: walk
        # down no-arg .copy() calls; anything else
        # (args, other calls) is unresolvable (None).
        # A copy of a proven-fresh root is fresh.
        while isinstance(value, ast.Call) \
                and isinstance(value.func, ast.Attribute) \
                and value.func.attr == "copy" \
                and not value.args and not value.keywords:
            value = value.func.value
        return value

    def _fresh_seed(value):
        # a value that IS a fresh container (or a chain
        # of copies — resolved by the caller through
        # _fresh_copy_root).
        if isinstance(value, (ast.Dict, ast.List,
                              ast.Set)):
            return True
        return isinstance(value, ast.Call) \
            and isinstance(value.func, ast.Name) \
            and value.func.id in ("dict", "list", "set") \
            and value.func.id not in rebound \
            and value.func.id not in module_attr_binds

    def classify_cap(name, bind):
        # readcap is DETECT-membership: unknown values
        # are seeds (fail closed — an unknown callable
        # may read); only provable non-capabilities
        # void. For-targets judge their iter (an empty
        # literal never runs — neutral; an all-constant
        # non-empty literal voids; anything else seeds).
        # Nested defs void only when provably harmless.
        _pos, kind, value = bind
        if kind == "for":
            if isinstance(value, (ast.Tuple, ast.List)):
                if not value.elts:
                    return (False, set(), False)
                if all(isinstance(elt, ast.Constant)
                       for elt in value.elts):
                    return (True, set(), False)
            return (False, set(), True)
        if kind == "def":
            if _def_harmless(value):
                return (True, set(), False)
            return (False, set(), True)
        if value is None:
            return (False, set(), True)
        if isinstance(value, ast.Constant):
            return (True, set(), False)
        if isinstance(value, ast.Name):
            if value.id in read_attrs:
                return (False, set(), True)
            return (False, {value.id}, False)
        if isinstance(value, ast.Attribute):
            if value.attr in read_attrs:
                return (False, set(), True)
            return (True, set(), False)
        return (False, set(), True)

    def classify_fresh(name, bind):
        # fresh is EXEMPT-membership (proven-fresh
        # containers skip descent): only proven shapes
        # seed; everything else voids (fail closed).
        _pos, kind, value = bind
        if kind != "plain" or value is None:
            return (True, set(), False)
        if isinstance(value, ast.Name):
            return (False, {value.id}, False)
        if isinstance(value, ast.Call):
            root = _fresh_copy_root(value)
            if root is value:
                # no copy chain: a direct builtin
                # constructor still seeds (dict()/list()/
                # set() build fresh storage); any other
                # call voids (fail-closed).
                if _fresh_seed(value):
                    return (False, set(), True)
                return (True, set(), False)
            if isinstance(root, ast.Name):
                return (False, {root.id}, False)
            if _fresh_seed(root):
                return (False, set(), True)
            return (True, set(), False)
        if _fresh_seed(value):
            return (False, set(), True)
        return (True, set(), False)

    outer_cap_memo = {}

    def outer_cap_in(scope):
        # order-free capability status for a scope
        # (outer scopes have unknowable timing): a name
        # is IN when any bind seeds it, directly or
        # through an IN peer chain (a call could
        # install before any clean rebind — fail
        # closed). Peers resolve through the lexical
        # outers, immediate enclosing scope included.
        # Unseeded cycles stay OUT. Memoized per scope
        # (the scope DAG is static within one
        # _binding_violations call).
        key = id(scope)
        if key not in outer_cap_memo:
            outers = [
                outer
                for outer in lexical_use_chain(scope)
                if not isinstance(outer, ast.ClassDef)]

            def resolve(peer):
                for outer in outers:
                    if peer in scope_binds[id(outer)]:
                        return peer in outer_cap_in(outer)
                return False

            binds = scope_binds[key]
            seeds = {}
            peers_of = {}
            for name, blist in binds.items():
                seed_any = False
                peers = set()
                for bind in blist:
                    _out, peers_one, seed = classify_cap(
                        name, bind)
                    seed_any = seed_any or seed
                    for peer in peers_one:
                        if peer == name:
                            continue
                        if peer in binds:
                            peers.add(peer)
                        elif resolve(peer):
                            seed_any = True
                seeds[name] = seed_any
                peers_of[name] = peers
            inside = {name for name, seed in seeds.items()
                      if seed}
            changed = True
            while changed:
                changed = False
                for name, peers in peers_of.items():
                    if name not in inside and any(
                            peer in inside
                            for peer in peers):
                        inside.add(name)
                        changed = True
            outer_cap_memo[key] = inside
        return outer_cap_memo[key]

    def caps_at(node, after_value=None):
        # read capabilities visible at a bind: the query
        # scope (lexical, class and lambda bodies
        # included) judges binds strictly before the
        # query position — last decisive bind wins (a
        # later clean rebind un-installs, a later seed
        # re-installs; neutral never-executed binds
        # fall through) — with copies resolved at the
        # copy position (a copy snapshots the value
        # then); an install inside a loop also sees
        # seeds anywhere in the loop body (some pass
        # installs them — back-edge). Outer scopes
        # resolve order-free ANY-seed (call timing
        # unknowable, fail-closed); shadowing names
        # stay decided by the query scope. A sibling
        # scope never leaks in; a module capability
        # used but never rebound locally still
        # resolves.
        # after_value (an install's RHS): the install
        # observes post-RHS state — RHS-internal binds
        # (walrus) are visible, but the statement's own
        # target binds (noted at stmt start) and, for
        # Assign, target-span walruses (bound after the
        # RHS) are not. For calls every earlier arg
        # evaluated first, so nothing is excluded.
        chain = lexical_use_chain(node)
        query = chain[0]
        qpos = (node.lineno, node.col_offset)
        stmt_start = qpos
        span_lo = span_end = None
        if after_value is not None:
            span_end = (after_value.end_lineno,
                        after_value.end_col_offset)
            qpos = span_end
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                span_lo = (after_value.lineno,
                           after_value.col_offset)
            else:
                span_lo = stmt_start
        qbinds = scope_binds[id(query)]
        window = None
        window_node = None
        current = node
        while id(current) in parents:
            current = parents[id(current)]
            if current is query:
                break
            if isinstance(current, (ast.For, ast.AsyncFor,
                                    ast.While)):
                window = ((current.lineno,
                           current.col_offset),
                          (current.end_lineno,
                           current.end_col_offset))
                window_node = current
        memo = {}

        def rhs_span(bind):
            # the operand-evaluation span of a bind's
            # own statement: from the RHS start to the
            # end of the bind's own (narrowed) operand.
            # Peers the bind reads resolve with it
            # visible (target binds note at stmt start,
            # but read as-of their operand: earlier
            # operands' walruses completed, later ones
            # did not). None when the bind has no
            # operand span.
            _bpos, _bkind, _bval = bind
            if _bkind not in ("plain", "for") \
                    or _bval is None:
                return None
            cursor = _bval
            while id(cursor) in parents:
                cursor = parents[id(cursor)]
                if isinstance(cursor, ast.Assign):
                    val = cursor.value
                    return ((val.lineno, val.col_offset),
                            (_bval.end_lineno,
                             _bval.end_col_offset))
                if isinstance(cursor, ast.AnnAssign) \
                        and cursor.value is not None:
                    val = cursor.value
                    return ((val.lineno, val.col_offset),
                            (_bval.end_lineno,
                             _bval.end_col_offset))
                if isinstance(cursor, (ast.For, ast.AsyncFor)):
                    it = cursor.iter
                    if (cursor.target.lineno,
                            cursor.target.col_offset) \
                            <= (_bval.lineno,
                                _bval.col_offset) \
                            <= (cursor.target.end_lineno,
                                cursor.target.end_col_offset):
                        # a target bind reads post-iterator
                        # state: the iterator completes
                        # before the target binds (binds
                        # within the iterator keep the
                        # operand-end cut).
                        return ((it.lineno, it.col_offset),
                                (it.end_lineno,
                                 it.end_col_offset))
                    return ((it.lineno, it.col_offset),
                            (_bval.end_lineno,
                             _bval.end_col_offset))
            return None

        def outer(name):
            for scope in chain[1:]:
                if name in scope_binds[id(scope)]:
                    return name in outer_cap_in(scope)
            return False

        def holds(name, pos, windowed, favor=None):
            # windowed (an install inside a loop): any
            # seed later in the window counts (some pass
            # installs it — a later kill never vetoes),
            # else the last decisive bind before pos
            # wins; copies resolve windowed when read
            # inside the window (their reads repeat
            # too) and snapshot pre-loop otherwise.
            # Windowless: the last decisive bind before
            # pos wins; neutral binds fall through to
            # earlier binds, then outward. Positions
            # strictly decrease along windowless
            # recursion, and memo keys pin windowed
            # cycles — both terminate.
            key = (name, pos, windowed, favor)
            if key in memo:
                return memo[key]
            # completion order, not walk order:
            # ast.walk is breadth-first, so a deeper
            # earlier bind would wrongly decide after
            # a later seed — and an assignment runs
            # RHS first, then each target in order,
            # evaluating (walrus effects) before
            # storing. Targets complete at RHS end
            # keyed by full target-leaf index path
            # (stores by their paired leaf, effects by
            # their deepest holding leaf — duplicates
            # un-tie across and within targets, last
            # target wins; identical multi-target
            # binds keep stability).
            def completion(bind, occ=0):
                bpos, kind, value = bind
                if kind != "plain" or value is None:
                    return (bpos, bpos, 0)
                node = value
                child = None
                walrus_end = None
                while id(node) in parents:
                    child = node
                    node = parents[id(node)]
                    if walrus_end is None \
                            and isinstance(
                                node, ast.NamedExpr) \
                            and node.target.id == name:
                        # a walrus completes when its
                        # value finishes (inside-out
                        # for nesting — the outer
                        # store lands last), not when
                        # it starts; a walrus inside
                        # an assignment target
                        # completes with that target
                        # (decided at the Assign).
                        walrus_end = (node.end_lineno,
                                      node.end_col_offset)
                    if isinstance(node, (ast.Assign,
                                         ast.AnnAssign)):
                        if (node.lineno, node.col_offset) \
                                == bpos \
                                and node.value is not None:
                            end = node.value
                            # per-leaf order: the store
                            # completes with its own
                            # target leaf (full index path
                            # — duplicates un-tie across
                            # and within targets, last
                            # target wins). Values alone
                            # cannot select the leaf:
                            # repeated targets reuse the
                            # same operand nodes, so the
                            # bind's occurrence index
                            # (note order is target order)
                            # selects the Nth matching
                            # occurrence.
                            tops = node.targets \
                                if isinstance(
                                    node, ast.Assign) \
                                else [node.target]
                            matches = []
                            for top_idx, top in enumerate(
                                    tops):
                                for leaf, operand in \
                                        _walk_pairs(
                                            top, node.value):
                                    if name not in _bound_names(
                                            leaf):
                                        continue
                                    if operand is value \
                                            or (operand.lineno,
                                                operand.col_offset) \
                                            <= (value.lineno,
                                                value.col_offset) \
                                            <= (operand.end_lineno,
                                                operand.end_col_offset):
                                        matches.append(
                                            (top_idx, top,
                                             leaf))
                            if matches:
                                top_idx, top, leaf = matches[
                                    min(occ,
                                        len(matches) - 1)]
                                path = [top_idx]
                                probe = top
                                while probe is not leaf \
                                        and isinstance(
                                            probe,
                                            (ast.Tuple,
                                             ast.List)):
                                    for i, elt in enumerate(
                                            probe.elts):
                                        if elt is leaf \
                                                or (elt.lineno,
                                                    elt.col_offset) \
                                                <= (leaf.lineno,
                                                    leaf.col_offset) \
                                                <= (elt.end_lineno,
                                                    elt.end_col_offset):
                                            path.append(i)
                                            probe = elt
                                            break
                                    else:
                                        break
                                if probe is leaf:
                                    return ((end.end_lineno,
                                             end.end_col_offset),
                                            tuple(path), 1)
                            return ((end.end_lineno,
                                     end.end_col_offset),
                                    (0,), 1)
                        targets = node.targets if isinstance(
                            node, ast.Assign) else [
                                node.target]
                        if child in targets \
                                and node.value \
                                is not None:
                            # the deepest target leaf
                            # holding the effect (full
                            # index path, same space as
                            # stores: within one target,
                            # leaves complete
                            # left-to-right, effects with
                            # their own leaf).
                            top = 0
                            for i, candidate in enumerate(
                                    targets):
                                if candidate is child:
                                    top = i
                                    break
                            path = [top]
                            target = child
                            while isinstance(
                                    target,
                                    (ast.Tuple, ast.List)):
                                for i, elt in enumerate(
                                        target.elts):
                                    if (elt.lineno,
                                            elt.col_offset) \
                                            <= bpos \
                                            <= (elt.end_lineno,
                                                elt.end_col_offset):
                                        path.append(i)
                                        target = elt
                                        break
                                else:
                                    break
                            end = node.value
                            return ((end.end_lineno,
                                     end.end_col_offset),
                                    tuple(path), 0)
                        if walrus_end is not None:
                            return (walrus_end,
                                    walrus_end, 0)
                        return (bpos, bpos, 0)
                    if isinstance(node, (ast.For,
                                         ast.AsyncFor)):
                        # the iterator completes before
                        # the target evaluates: every
                        # iterator bind lands before
                        # every target bind (phase 0
                        # vs 1 under the loop start),
                        # each phase ordered by
                        # completion within it. Body
                        # and orelse binds keep plain
                        # position order (they run
                        # after the target).
                        if child is node.iter:
                            end = walrus_end \
                                if walrus_end is not None \
                                else bpos
                            return ((node.lineno,
                                     node.col_offset),
                                    (0, end), 0)
                        if child is node.target:
                            end = walrus_end \
                                if walrus_end is not None \
                                else bpos
                            return ((node.lineno,
                                     node.col_offset),
                                    (1, end), 0)
                    if isinstance(node, ast.stmt):
                        if walrus_end is not None:
                            return (walrus_end,
                                    walrus_end, 0)
                        return (bpos, bpos, 0)
                if walrus_end is not None:
                    return (walrus_end, walrus_end, 0)
                return (bpos, bpos, 0)

            # occurrence index: same-statement binds of
            # this name sharing one value node (repeated
            # targets reuse operands) select the Nth
            # matching target occurrence in note order
            # (the walker notes targets in completion
            # order) — values alone would all select
            # the first.
            raw_binds = qbinds.get(name, []) \
                + comp_binds_by_name.get(name, [])
            occ_of = {}
            counters = {}
            for idx, bind in enumerate(raw_binds):
                _bpos, _bkind, _bval = bind
                if _bkind == "plain" and _bval is not None:
                    okey = (_bpos, id(_bval))
                    occ_of[idx] = counters.get(okey, 0)
                    counters[okey] = counters.get(okey, 0) + 1
                else:
                    occ_of[idx] = 0
            blist = sorted(
                enumerate(raw_binds),
                key=lambda pair: completion(
                    pair[1], occ_of[pair[0]]))
            blist = [bind for _, bind in blist]

            def sees(bind):
                # what the query observes: strictly
                # before pos normally; post-RHS (pre-
                # statement plus the value span, target
                # binds excluded) in after_value mode.
                # Favor adds a peer bind's own operand
                # span (a target bind reads post-RHS
                # state — RHS walruses included — even
                # though it notes at stmt start).
                # Binds noted inside the operand span
                # judge by completion (end) alone, not
                # start: an enclosing walrus starts
                # before the read but its store is
                # still pending (it completes with its
                # value, after the operand) — only a
                # store finished by the operand end is
                # visible. Comprehension loop variables
                # (side table, keyed by their iterable)
                # are visible anywhere inside their own
                # comprehension span except inside
                # their own iterable (which reads the
                # enclosing scope — the element
                # precedes the generators textually
                # but runs after them).
                bpos = bind[0]
                if bind[2] is not None:
                    centry = comp_spans.get(id(bind[2]))
                    if centry is not None:
                        cspan, istart, iend = centry
                        if not (cspan[0] <= pos
                                <= cspan[1]):
                            return False
                        return not (istart <= pos
                                    <= iend)
                if favor is not None \
                        and favor[0] <= bpos:
                    if bpos >= favor[1]:
                        return False
                    if bind[2] is None:
                        return True
                    return (bind[2].end_lineno,
                            bind[2].end_col_offset) \
                        <= favor[1]
                if after_value is None:
                    if bpos < pos:
                        return True
                elif bpos < stmt_start:
                    if bpos < pos:
                        return True
                elif span_lo <= bpos < min(pos, span_end):
                    return True
                return False
            memo[key] = False
            if windowed and window is not None:
                wstart, wend = window
                single = False
                if isinstance(window_node, (ast.For,
                                            ast.AsyncFor)):
                    it = window_node.iter
                    single = (it.lineno, it.col_offset) \
                        <= pos <= (it.end_lineno,
                                   it.end_col_offset)
                later = [bind for bind in blist
                         if wstart <= bind[0] < wend
                         and bind[0] >= pos
                         and (not single or sees(bind))]
                for _bpos, _kind, _value in later:
                    _out, peers, seed = classify_cap(
                        name, (_bpos, _kind, _value))
                    if seed:
                        memo[key] = True
                        return True
                    for peer in peers:
                        if peer == name:
                            continue
                        if holds(peer, _bpos, True,
                                 rhs_span((_bpos, _kind,
                                           _value))):
                            memo[key] = True
                            return True
                for _bpos, _kind, _value in reversed(
                        [bind for bind in blist
                         if sees(bind)]):
                    out, peers, seed = classify_cap(
                        name, (_bpos, _kind, _value))
                    if out:
                        return False
                    if seed:
                        memo[key] = True
                        return True
                    decided = False
                    for peer in peers:
                        if peer == name:
                            continue
                        decided = True
                        if not holds(peer, _bpos,
                                     _bpos >= wstart,
                                     rhs_span((_bpos, _kind,
                                               _value))):
                            return False
                    if decided:
                        memo[key] = True
                        return True
                    # neutral: try earlier binds.
                result = outer(name)
                memo[key] = result
                return result
            visible = [bind for bind in blist
                       if sees(bind)]
            if not visible:
                result = outer(name)
                memo[key] = result
                return result
            for _bpos, _kind, _value in reversed(visible):
                out, peers, seed = classify_cap(
                    name, (_bpos, _kind, _value))
                if out:
                    return False
                if seed:
                    memo[key] = True
                    return True
                decided = False
                for peer in peers:
                    if peer == name:
                        continue
                    decided = True
                    if not holds(peer, _bpos, False,
                                 rhs_span((_bpos, _kind,
                                           _value))):
                        return False
                if decided:
                    memo[key] = True
                    return True
                # neutral (never runs): try earlier binds.
            result = outer(name)
            memo[key] = result
            return result

        names = set(qbinds)
        for scope in chain[1:]:
            names.update(scope_binds[id(scope)])
        # comprehension loop variables (span-gated in
        # sees, so names bound only inside one still
        # resolve at uses inside it).
        names.update(comp_binds_by_name)
        # fixpoint: True verdicts are sound (a True never
        # derives from an in-progress False), but False
        # ones may be cycle-poisoned (a copy cycle seen
        # mid-resolution) — drop them and re-run until
        # the held set stops growing. Without this the
        # verdict depends on evaluation order.
        held = set()
        while True:
            for key in [key for key, val in memo.items()
                        if not val]:
                del memo[key]
            new = {name for name in names
                   if holds(name, qpos, True)}
            if new <= held:
                held |= new
                break
            held |= new
        return held

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
            for leaf in _target_leaves(target):
                found, key = _namespace_store(leaf)
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
                    for leaf, value in _walk_pairs(target,
                                                   stored):
                        if isinstance(leaf, ast.Attribute):
                            module_attr_binds.add(leaf.attr)
                            if not isinstance(leaf.value,
                                              ast.Name):
                                # a computed root may be a
                                # module namespace
                                # (sys.modules[k].run_logged
                                # rebinds the bare name) —
                                # mirror the setattr rule.
                                rebound.add(leaf.attr)
                            builtins_hit = _builtins_attr(leaf)
                            if builtins_hit is not None:
                                builtins_attr_binds.add(
                                    builtins_hit)
                            if read_ref(value, caps_at(
                                    top, after_value=stored)):
                                module_rebound_methods.add(
                                    leaf.attr)
        # For/With bind fresh values to attribute
        # targets too (for P.r in ... / with X as P.r):
        # the element is unknowable, so the bind joins
        # unconditionally (fail-closed). AugAssign to an
        # attribute target installs whatever its dunder
        # returns (x.attr |= v runs __or__/__ror__,
        # which may return anything — a proven fresh
        # capability installer), so it joins both sets
        # unconditionally too. Every other form binds
        # plain names only.
        if isinstance(top, (ast.For, ast.AsyncFor)):
            for leaf in _target_leaves(top.target):
                if isinstance(leaf, ast.Attribute):
                    module_attr_binds.add(leaf.attr)
                    module_rebound_methods.add(leaf.attr)
                    if not isinstance(leaf.value, ast.Name):
                        rebound.add(leaf.attr)
                    builtins_hit = _builtins_attr(leaf)
                    if builtins_hit is not None:
                        builtins_attr_binds.add(builtins_hit)
        if isinstance(top, (ast.With, ast.AsyncWith)):
            for item in top.items:
                if item.optional_vars is not None:
                    for leaf in _target_leaves(
                            item.optional_vars):
                        if isinstance(leaf, ast.Attribute):
                            module_attr_binds.add(leaf.attr)
                            module_rebound_methods.add(leaf.attr)
                            if not isinstance(
                                    leaf.value, ast.Name):
                                rebound.add(leaf.attr)
                            builtins_hit = _builtins_attr(leaf)
                            if builtins_hit is not None:
                                builtins_attr_binds.add(
                                    builtins_hit)
        if isinstance(top, ast.AugAssign):
            for leaf in _target_leaves(top.target):
                if isinstance(leaf, ast.Attribute):
                    module_attr_binds.add(leaf.attr)
                    module_rebound_methods.add(leaf.attr)
                    if not isinstance(leaf.value, ast.Name):
                        rebound.add(leaf.attr)
                    builtins_hit = _builtins_attr(leaf)
                    if builtins_hit is not None:
                        builtins_attr_binds.add(builtins_hit)
            is_ior, ior_keys, ior_dynamic = \
                _namespace_ior_keys(top)
            if is_ior:
                if ior_dynamic:
                    dynamic_rebinds.append(top)
                rebound.update(ior_keys)
        if isinstance(top, ast.Call):
            is_mutator, keys, dynamic = \
                _namespace_mutator_keys(top)
            if is_mutator:
                if dynamic:
                    dynamic_rebinds.append(top)
                rebound.update(keys)
                if isinstance(top.func.value, ast.Name) \
                        and top.func.value.id == "dict" \
                        and top.args \
                        and _namespace_expr(top.args[0]) \
                        and not _namespace_expr(
                            top.func.value):
                    tentative_dict_unbound.append(top)
            elif _passes_namespace(top):
                dynamic_rebinds.append(top)
            if isinstance(top.func, ast.Name) \
                    and top.func.id in ns_mutator_aliases:
                # a call through an unbound mutator
                # attribute (upd = ns.update): the keys
                # are unresolvable — fail closed.
                dynamic_rebinds.append(top)
        if isinstance(top, ast.Call) \
                and isinstance(top.func, ast.Name) \
                and top.func.id == "setattr" \
                and len(top.args) >= 3:
            named = top.args[1]
            if isinstance(named, ast.Constant) \
                    and isinstance(named.value, str):
                module_attr_binds.add(named.value)
                if isinstance(top.args[0], ast.Name) \
                        and (top.args[0].id == "builtins"
                             or _surface_alias_at(
                                 surfaces, parents,
                                 top.args[0],
                                 top.args[0].id)
                             == "builtins"
                             or _module_alias_root(
                                 surfaces, parents,
                                 scope_binds, top.args[0],
                                 top.args[0].id)
                             == "builtins"):
                    builtins_attr_binds.add(named.value)
                if not isinstance(top.args[0], ast.Name):
                    rebound.add(named.value)
                elif read_ref(top.args[2], caps_at(
                        top, after_value=top.args[2])):
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
                and (id(top) not in top_level_defs
                     or top.name not in _LANE_DEFINED_SINKS):
            # a top-level definition counts as a rebind
            # unless it IS one of the sink defs the lane
            # actually defines (wholesale replacement of
            # those is body verification, out of scope);
            # anything else shadowing a sink/consumer/
            # builtin name (def print, class dict)
            # voids its trust.
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
    dict_trusted = "dict" not in rebound \
        and "dict" not in module_attr_binds
    if not dict_trusted:
        # the tentative unbound-dict sites parsed
        # against a rebound dict: fail them closed
        # (their keys stay trusted — voiding is
        # fail-closed — but the call itself fires).
        dynamic_rebinds.extend(tentative_dict_unbound)
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
            # a path-builder call (str/join/...) with
            # tainted arguments counts too: a NESTED
            # tainted argument (str(log.absolute()))
            # does not fire at its own construction
            # site, so the bound name must stay tainted.
            # Any other call's result abstracts its
            # inputs (verdicts, counts, child bytes),
            # so spreading through it would drown the
            # audit — see _PATH_BUILDERS. (Sanctioned
            # derived-path calls spread like any other;
            # their publish exemption rides provenance
            # in sanctioned_shape/sanction_value below,
            # not untaintedness here.)
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
            if isinstance(value, ast.Call):
                if isinstance(value.func, ast.Attribute) \
                        and tainted_in(value.func.value,
                                       tainted):
                    return True
                if _call_simple_name(value.func) \
                        not in _PATH_BUILDERS:
                    return False
                return any(tainted_in(arg, tainted)
                           for arg in value.args) \
                    or any(tainted_in(keyword.value, tainted)
                           for keyword in value.keywords)
            return False

        # Value-agnostic binding scans. The first
        # collects attribute binds (any *.attr bind,
        # for the privileged relative_to name); the
        # second feeds alias groups (a name bound to a
        # bare name shares its object) and the shared
        # scope-pruned provenance map (copy components
        # with a seed and no kills hold the sanctioned
        # string). Split because provenance judges name
        # trust, which needs the attribute binds first.
        # Events replay in position order with pair-order
        # sequences and same-position batches atomic
        # (simultaneous copies read the pre-batch
        # groups); any other binding form kills
        # membership (rebind-kill). Bindings inside
        # nested scopes prune (their binds are local —
        # only nonlocal writes through them are missed,
        # see the known-narrow list). Namespace-mutator
        # calls (globals().update(a=box)) neither alias
        # nor kill here: rebinding through them is
        # tracked (see the module walk), but object
        # identity through them is out of scope.
        func_attr_binds = set()
        for node in ast.walk(func):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(
                    node, ast.Assign) else [node.target]
                for target in targets:
                    for leaf in _target_leaves(target):
                        if isinstance(leaf, ast.Attribute):
                            func_attr_binds.add(leaf.attr)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                for leaf in _target_leaves(node.target):
                    if isinstance(leaf, ast.Attribute):
                        func_attr_binds.add(leaf.attr)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        for leaf in _target_leaves(
                                item.optional_vars):
                            if isinstance(leaf, ast.Attribute):
                                func_attr_binds.add(leaf.attr)
            elif isinstance(node, ast.AugAssign):
                for leaf in _target_leaves(node.target):
                    if isinstance(leaf, ast.Attribute):
                        func_attr_binds.add(leaf.attr)
            elif isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Name) \
                    and node.func.id == "setattr" \
                    and len(node.args) >= 3 \
                    and isinstance(node.args[1], ast.Constant) \
                    and isinstance(node.args[1].value, str):
                func_attr_binds.add(node.args[1].value)
        attr_binds = module_attr_binds | func_attr_binds

        def sanctioned_shape(value):
            # the exact sanctioned call:
            # str(x.relative_to(...)) with trustworthy
            # names (a rebound str/relative_to voids the
            # shape here and at the publish check alike;
            # a method def named relative_to lands in
            # rebound, so it voids too; an attribute
            # bind of either name voids as well —
            # builtins.str = ... rebinds the bare call
            # every module resolves through).
            return isinstance(value, ast.Call) \
                and isinstance(value.func, ast.Name) \
                and value.func.id == "str" \
                and len(value.args) == 1 \
                and not value.keywords \
                and isinstance(value.args[0], ast.Call) \
                and isinstance(value.args[0].func, ast.Attribute) \
                and value.args[0].func.attr == "relative_to" \
                and "str" not in rebound \
                and "str" not in attr_binds \
                and "relative_to" not in attr_binds \
                and "relative_to" not in rebound

        # Alias events from a pruned walk of the same
        # scope (nested binds are local — they neither
        # join nor detach outer objects; lambda bodies
        # prune whole). Events carry an emission
        # sequence so same-position batches replay in
        # pair order (the sort is by position only and
        # the sequence breaks ties — never the peer
        # spelling).
        alias_events = []
        event_chain = {}
        seq = [0]

        def emit(node, kind, name, peer, okey=None,
                 src=None):
            # events sort by (line, col, seq); okey orders
            # a same-statement store's prefix: (phase,
            # line, col) with RHS effects (phase 0)
            # before target binds (phase 1). Assign
            # targets carry their operand position too
            # (phase, leaf line/col, operand line/col)
            # so each target snapshots its peer when
            # its operand evaluates. Default is the
            # emitting node's own target phase.
            # The ancestor chain (id, typename) from the
            # bind site up to func decides loop-relative
            # overwrite in the loop union (a re-point
            # under If/Try/Match/short-circuit or an
            # inner loop never overwrites). The chain
            # starts AT the bind site itself, so a bind
            # owned by a loop header (a for-target)
            # counts as unconditional in that loop.
            if okey is None:
                okey = (1, node.lineno, node.col_offset)
            if src is None:
                src = node
            chain = [(id(src), type(src).__name__)]
            current = src
            while current is not func:
                if id(current) not in parents:
                    break
                current = parents[id(current)]
                chain.append((id(current),
                              type(current).__name__))
            alias_events.append((node.lineno, node.col_offset,
                                 seq[0], kind, name, peer,
                                 okey))
            event_chain[seq[0]] = chain
            seq[0] += 1

        def kill_binding(name, node):
            emit(node, "kill", name, None)

        def trusted_ctor(name):
            return name in ("dict", "list", "set") \
                and name not in rebound \
                and name not in module_attr_binds

        def walrus_event(stmt, named):
            inner = _unwrap_walrus(named.value)
            # the effect lands at completion (the
            # walrus end — inside-out for nesting),
            # not at its start.
            okey = (0, named.end_lineno,
                    named.end_col_offset)
            if isinstance(inner, ast.Name):
                emit(stmt, "alias", named.target.id,
                     inner.id, okey, named)
            else:
                sources = _copy_source_names(
                    inner, trusted_ctor)
                if sources:
                    for source in sources:
                        emit(stmt, "copy", named.target.id,
                             source, okey, named)
                elif _fresh_value(inner, trusted_ctor):
                    emit(stmt, "fresh", named.target.id,
                         None, okey, named)
                else:
                    emit(stmt, "kill", named.target.id,
                         None, okey, named)

        def kill_target(target, node):
            for leaf in _target_leaves(target):
                found, key = _namespace_store(leaf)
                if found:
                    if key is not None:
                        kill_binding(key, node)
                else:
                    for name in _bound_names(leaf):
                        kill_binding(name, node)

        skip = _scope_skip_ids(func)
        claimed = set()
        # RHS-first: named expressions inside value
        # subtrees (and nested kept parts, which
        # evaluate enclosing) bind before the statement
        # binds its targets — pre-emit them keyed at
        # the statement (phase 0) so same-statement
        # order replays evaluation order.
        for node in ast.walk(func):
            if id(node) in skip:
                continue
            anchor = None
            values = []
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value is not None:
                    values = [node.value]
                    anchor = node
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                values = [node.iter]
                anchor = node
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                values = [item.context_expr
                          for item in node.items]
                anchor = node
            elif isinstance(node, (ast.FunctionDef,
                                   ast.AsyncFunctionDef,
                                   ast.ClassDef, ast.Lambda)) \
                    and node is not func:
                anchor = node
                keep = _kept_parts(node)
                for sub in ast.walk(node):
                    if id(sub) in keep and isinstance(
                            sub, ast.NamedExpr):
                        walrus_event(anchor, sub)
                        claimed.add(id(sub))
                continue
            for value in values:
                for sub in ast.walk(value):
                    if isinstance(sub, ast.NamedExpr):
                        walrus_event(anchor, sub)
                        claimed.add(id(sub))
        for node in ast.walk(func):
            if id(node) in skip or id(node) in claimed:
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if value is None:
                    continue
                targets = node.targets if isinstance(
                    node, ast.Assign) else [node.target]
                for target in targets:
                    for leaf, val in _walk_pairs(target,
                                                 value):
                        found, key = _namespace_store(leaf)
                        if found and key is not None:
                            target_names = [key]
                            is_key = True
                        elif found:
                            continue
                        else:
                            target_names = list(
                                _bound_names(leaf))
                            is_key = False
                        plain = (not is_key) \
                            and isinstance(leaf, ast.Name)
                        # a target paired with a walrus
                        # binds the walrus value (a =
                        # (t := v) binds a to v).
                        # the operand position snapshots
                        # the peer when the operand
                        # evaluates (captured before the
                        # unwrap: evaluation starts at
                        # the operand, walrus included).
                        okey = (1, leaf.lineno,
                                leaf.col_offset,
                                val.lineno, val.col_offset)
                        val = _unwrap_walrus(val)
                        for name in target_names:
                            if isinstance(val, ast.Name) \
                                    and (plain or is_key):
                                emit(node, "alias", name,
                                     val.id, okey, leaf)
                            elif plain:
                                sources = _copy_source_names(
                                    val, trusted_ctor)
                                if sources:
                                    for source in sources:
                                        emit(node, "copy",
                                             name, source,
                                             okey, leaf)
                                elif _fresh_value(
                                        val, trusted_ctor):
                                    emit(node, "fresh", name,
                                         None, okey, leaf)
                                else:
                                    emit(node, "kill", name,
                                         None, okey, leaf)
                            else:
                                kill_binding(name, node)
            elif isinstance(node, ast.NamedExpr):
                walrus_event(node, node)
            elif isinstance(node, ast.AugAssign):
                # Augmented assignment may rebind
                # (immutables) or mutate in place
                # (containers): for object identity the
                # sound direction keeps the group (no
                # alias event — a store through it lands
                # in the position-current group).
                pass
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                # a for-target over a load-free iter
                # binds fresh-anonymous items every
                # pass (a header separator); anything
                # else may re-yield a rebound object.
                if _load_free(node.iter, trusted_ctor):
                    for leaf in _target_leaves(node.target):
                        found, key = _namespace_store(leaf)
                        if found:
                            if key is not None:
                                emit(node, "fresh", key,
                                     None)
                        else:
                            for name in _bound_names(leaf):
                                emit(node, "fresh", name,
                                     None)
                else:
                    kill_target(node.target, node)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        kill_target(item.optional_vars, node)
            elif isinstance(node, ast.ExceptHandler):
                if node.name:
                    kill_binding(node.name, node)
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    for name in _match_names(case.pattern):
                        kill_binding(name, node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    kill_binding(alias.asname
                                 or alias.name.split(".")[0], node)
            elif isinstance(node, (ast.FunctionDef,
                                   ast.AsyncFunctionDef,
                                   ast.ClassDef)) \
                    and node is not func:
                kill_binding(node.name, node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for name in node.names:
                    kill_binding(name, node)
        for param in _func_params(func):
            kill_binding(param, func)

        # Positional alias snapshots: events replay in
        # (line, col, seq) order; each same-position
        # batch applies atomically (simultaneous copies
        # read the pre-batch groups — a swap exchanges
        # objects), except a batch rebinding one name
        # twice, which snapshots every RHS identity up
        # front and then applies targets in pair order
        # (the last store wins, RHS reads pre-batch).
        # A rebind detaches first (alias = fresh leaves
        # the old group instead of merging both objects
        # into one). Copies of a peer that held no
        # known object share one anonymous pre-batch
        # identity (they still share the old object
        # even when the peer itself is re-pointed).
        # A store lands in the union of groups its name
        # holds from just before its statement through
        # the enclosing loop (straight-line: just its
        # statement) — pre-retarget stores hit the old
        # peers, post-retarget stores spare them, and
        # loop back-edges re-reach joined objects — so
        # no end-state propagation is needed.
        def detach(groups, copies, name):
            owned = groups.pop(name, None)
            if owned is not None:
                owned.discard(name)
            copies.pop(name, None)

        def apply_events(evts, groups, copies, pos):
            # one event list (a full batch or a
            # same-statement prefix) onto groups/copies
            # in place. Walrus effects and target
            # operand reads interleave in evaluation
            # order — each alias/copy target snapshots
            # its peer exactly when its operand
            # evaluates (a later walrus in the same RHS
            # must not rewrite an earlier read; ties go
            # to the walrus, which produces the value
            # read) — then targets apply: duplicate
            # names in pair order (the last store
            # wins), unique names atomically. Unknown
            # peers invent an identity per (peer,
            # walrus-generation), pooled across same-
            # state readers and registered so a later
            # rebind detaches the peer from it; a lone
            # reader of a re-pointed unknown stands
            # alone. Copies propagate through aliases
            # (a name joined to a copy shares its
            # sources) and die on rebind; a copy of
            # a copy keeps the ORIGINAL source and
            # position (both share the descendants held
            # then).
            first = sorted(
                (event for event in evts
                 if event[6][0] == 0),
                key=lambda event: event[6])
            rest = [event for event in evts
                    if event[6][0] != 0]

            def operand_of(event):
                okey = event[6]
                if len(okey) > 4:
                    return (okey[3], okey[4])
                # no operand recorded (defensive — all
                # Assign targets carry one): snapshot
                # after every walrus, as before.
                return (pos[0] + 10 ** 6, 0)

            gen = {}

            def apply_first(event):
                _, _, _, kind, name, peer, _ = event
                # capture the source identity BEFORE
                # detaching: a self-walrus (a := a)
                # otherwise destroys the relationship
                # it reads (same for copy provenance).
                taken = groups.get(peer)
                had = peer in copies
                seen = set(copies.get(peer, ()))
                if kind == "alias":
                    detach(groups, copies, name)
                    if taken is None:
                        taken = {peer}
                        groups[peer] = taken
                    taken.add(name)
                    groups[name] = taken
                    if had:
                        copies[name] = set(seen)
                elif kind == "copy":
                    detach(groups, copies, name)
                    if had:
                        copies[name] = set(seen)
                    else:
                        copies[name] = {
                            (peer, pos,
                             frozenset(taken or ())
                             or frozenset({peer}))}
                else:
                    detach(groups, copies, name)
                gen[name] = gen.get(name, 0) + 1

            snaps = {}
            pools = {}
            walrus_at = 0
            snapshots = sorted(
                (event for event in rest
                 if event[3] in ("alias", "copy")),
                key=operand_of)
            for event in snapshots:
                opos = operand_of(event)
                while walrus_at < len(first) \
                        and first[walrus_at][6][1:] <= opos:
                    apply_first(first[walrus_at])
                    walrus_at += 1
                _, _, _, kind, name, peer, _ = event
                if kind == "alias":
                    found = groups.get(peer)
                    if found is None:
                        poolkey = (peer, gen.get(peer, 0))
                        if poolkey in pools:
                            found = pools[poolkey]
                        else:
                            found = {peer}
                            groups[peer] = found
                            pools[poolkey] = found
                    snaps[id(event)] = (
                        found, peer in copies,
                        set(copies.get(peer, ())))
                else:
                    # the seed captures the peer's group
                    # AT the operand (an RHS walrus may
                    # re-point it later in the same RHS;
                    # unknown peers seed themselves, as
                    # group_at's fallback did).
                    snaps[id(event)] = (
                        None, peer in copies,
                        set(copies.get(peer, ())),
                        frozenset(groups.get(peer, ()))
                        or frozenset({peer}))
            while walrus_at < len(first):
                apply_first(first[walrus_at])
                walrus_at += 1
            if not rest:
                return
            names = [event[4] for event in rest]
            if len(set(names)) < len(names):
                for event in rest:
                    _, _, _, kind, name, peer, _ = event
                    if kind == "alias":
                        detach(groups, copies, name)
                        taken, had, seen = snaps[id(event)]
                        taken.add(name)
                        groups[name] = taken
                        if had:
                            copies[name] = set(seen)
                    elif kind == "copy":
                        detach(groups, copies, name)
                        _, had, seen, oseed = snaps[id(event)]
                        if had:
                            copies[name] = set(seen)
                        else:
                            copies[name] = {(peer, pos, oseed)}
                    else:
                        detach(groups, copies, name)
            else:
                for _, _, _, _kind, name, _peer, _ in rest:
                    detach(groups, copies, name)
                for event in rest:
                    _, _, _, kind, name, peer, _ = event
                    if kind == "alias":
                        taken, had, seen = snaps[id(event)]
                        taken.add(name)
                        groups[name] = taken
                        if had:
                            copies[name] = set(seen)
                    elif kind == "copy":
                        _, had, seen, oseed = snaps[id(event)]
                        if had:
                            copies[name] = set(seen)
                        else:
                            copies[name] = {(peer, pos, oseed)}
                for (peer, _), pooled in pools.items():
                    # a lone reader of a re-pointed
                    # unknown stands alone (ungrouped),
                    # as simultaneous singletons did.
                    if peer not in pooled \
                            and len(pooled) < 2:
                        for member in list(pooled):
                            if groups.get(member) is pooled:
                                del groups[member]

        alias_events.sort()
        alias_snapshots = []
        groups = {}
        copies = {}
        index = 0
        while index < len(alias_events):
            pos = alias_events[index][:2]
            batch = []
            while index < len(alias_events) \
                    and alias_events[index][:2] == pos:
                batch.append(alias_events[index])
                index += 1
            apply_events(batch, groups, copies, pos)
            alias_snapshots.append(
                (pos, {name: frozenset(members)
                       for name, members in groups.items()},
                 {name: frozenset(sources)
                  for name, sources in copies.items()}))

        def snap_at(line, col, strict):
            # last snapshot at or before the position
            # (strict: strictly before), or None.
            found = None
            for (sline, scol), gsnap, csnap in \
                    alias_snapshots:
                if strict:
                    before = (sline, scol) < (line, col)
                else:
                    before = (sline, scol) <= (line, col)
                if before:
                    found = (gsnap, csnap)
                else:
                    break
            return found

        def group_at(name, line, col, strict=False):
            # members sharing name's object at (line,
            # col): the last snapshot at or before the
            # position (strict: strictly before).
            # Ungrouped names stand alone.
            found = snap_at(line, col, strict)
            if found is None:
                return frozenset({name})
            return found[0].get(name, frozenset({name}))

        def copies_at(name, line, col, strict=False):
            # shallow-copy sources of name at (line,
            # col): {(source, copy_pos, seed)} — names
            # share the descendants the source held
            # at the copy (seed: the source's group
            # at operand evaluation, itself for
            # unknown sources). Unknown names share
            # nothing.
            found = snap_at(line, col, strict)
            if found is None:
                return frozenset()
            return found[1].get(name, frozenset())

        loop_spans = []
        for maybe_loop in ast.walk(func):
            if isinstance(maybe_loop, (ast.For, ast.AsyncFor,
                                       ast.While)):
                loop_spans.append(
                    ((maybe_loop.lineno,
                      maybe_loop.col_offset),
                     (maybe_loop.end_lineno,
                      maybe_loop.end_col_offset),
                     maybe_loop))

        def overwrites(other, loop_id):
            # an unconditional re-point in the loop:
            # no If/Try/Match/short-circuit or inner
            # loop between the bind and the loop
            # (With and scope crossings transparent).
            for anc_id, typename in event_chain[
                    other[2]]:
                if anc_id == loop_id:
                    return True
                if typename in ("If", "Try", "TryStar",
                                "Match", "IfExp",
                                "BoolOp",
                                "comprehension",
                                "For", "AsyncFor",
                                "While"):
                    return False
            return False

        def loop_union_component(root, node, skip=()):
            # names joined with root anywhere in the
            # loops enclosing the store: back-edges
            # compose joins across iterations (a = b
            # then b = safe leaves a joined to safe on
            # the next pass). A join drops out when a
            # later bind of the name overwrites it
            # before the store observes (same-batch
            # later sequence wins; a later unconditional
            # re-point at or before the store kills the
            # join), when the peer moved on
            # simultaneously while holding no known
            # object (anonymous old-object sharing —
            # replay covers that), or when the peer is
            # unconditionally rebound to a fresh object
            # between the pairing and the store (the
            # edge names the pairing-time object, not
            # the current one). Anything else
            # (conditional re-points, back-edge binds,
            # peer re-points to another name or an
            # unknown value) stays joined (fail-closed).
            batch_names = {}
            for event in alias_events:
                batch_names.setdefault(
                    event[:2], set()).add(event[4])

            pairs = []
            here = (node.lineno, node.col_offset)
            for span_start, span_end, loop in loop_spans:
                if not span_start <= here <= span_end:
                    continue
                if id(loop) in skip:
                    continue
                loop_id = id(loop)
                for event in alias_events:
                    if event[3] != "alias":
                        continue
                    epos = event[:2]
                    if not span_start <= epos <= span_end:
                        continue
                    name, peer = event[4], event[5]
                    if any(other[:2] == epos
                           and other[2] > event[2]
                           and other[4] == name
                           for other in alias_events):
                        continue
                    if any(other[:2] > epos
                           and other[:2] <= here
                           and other[4] == name
                           and overwrites(other, loop_id)
                           for other in alias_events
                           if span_start <= other[:2]
                           <= span_end):
                        continue
                    # the right endpoint keeps its
                    # pairing-time identity: an
                    # unconditional fresh rebind of the
                    # peer between the pairing and the
                    # store retires the edge (a = box
                    # then box = {} leaves a joined to
                    # the old box, not the new one). A
                    # re-point to another name, a copy,
                    # or an unknown value keeps the edge
                    # (the next iteration may re-pair;
                    # fail-closed).
                    if any(other[:2] > epos
                           and other[:2] <= here
                           and other[3] == "fresh"
                           and other[4] == peer
                           and overwrites(other, loop_id)
                           for other in alias_events
                           if span_start <= other[:2]
                           <= span_end):
                        continue
                    if peer in batch_names[epos]:
                        pre = snap_at(epos[0], epos[1],
                                      strict=True)
                        if pre is None \
                                or peer not in pre[0]:
                            continue
                    pairs.append((name, peer))
            parent = {}

            def find(name):
                while parent.get(name, name) != name:
                    name = parent[name]
                return name

            for left, right in pairs:
                # both endpoints registered: a right-only
                # name must enumerate as a member, not
                # vanish as a bare union value.
                rroot = find(right)
                parent[find(left)] = rroot
                parent.setdefault(rroot, rroot)
            if root not in parent:
                return {root}
            return {name for name in parent
                    if find(name) == find(root)}

        def window_union(name, start, stop):
            mates = set(group_at(name, start[0], start[1],
                                 strict=True))
            for (sline, scol), gsnap, _ in alias_snapshots:
                if (sline, scol) <= start:
                    continue
                if stop is not None \
                        and (sline, scol) > stop:
                    break
                if name in gsnap:
                    mates.update(gsnap[name])
            return mates

        def reaches(pos, stop):
            # True when pos runs whenever stop does: no
            # conditional, loop, try, match or scope
            # boundary sits between them (an unbounded
            # stop never reaches).
            if stop is None:
                return False
            for node in ast.walk(func):
                if not isinstance(node, (ast.If, ast.For,
                                         ast.AsyncFor,
                                         ast.While, ast.Try,
                                         ast.TryStar,
                                         ast.Match,
                                         ast.FunctionDef,
                                         ast.AsyncFunctionDef,
                                         ast.Lambda,
                                         ast.ClassDef)):
                    continue
                nstart = (node.lineno, node.col_offset)
                nend = (node.end_lineno, node.end_col_offset)
                if nstart <= pos <= nend \
                        and not (nstart <= stop <= nend):
                    return False
            return True

        def same_object(scope, name, target, horizon,
                        seen):
            # True when `name` provably denotes the
            # `target` object just before `horizon` in
            # `scope`: spelling-equal, or transitively
            # bound through plain-Name binds whose edges
            # are still live (no reaching non-preserving
            # rebind between the edge and the horizon —
            # a historical alias proves nothing once
            # rebased; conditional binds count —
            # fail-closed). Copy-forms, calls and defs
            # break the chain: a copy is not its source
            # (a copy-peer kill at depth >= 2 is a
            # documented miss; at depth 1 the copy's top
            # is unrelated, so killing there is exact).
            if name == target:
                return True
            if name in seen:
                return False
            seen.add(name)
            for bpos, bkind, bval in scope_binds.get(
                    id(scope), {}).get(name, []):
                if not bpos < horizon:
                    continue
                if bkind != "plain":
                    continue
                bval = _unwrap_walrus(bval)
                if not isinstance(bval, ast.Name):
                    continue
                if edge_broken(scope, name, bpos, horizon,
                               seen):
                    continue
                if same_object(scope, bval.id, target, bpos,
                                seen):
                    return True
            return False

        def edge_broken(scope, name, bpos, horizon, seen):
            # a reaching rebind of `name` strictly after
            # the edge that does not itself preserve the
            # edge's object severs it (termination: the
            # shared `seen` bounds the mutual recursion
            # with same_object).
            for kpos, kkind, kvalue in scope_binds.get(
                    id(scope), {}).get(name, []):
                if not bpos < kpos <= horizon:
                    continue
                if not reaches(kpos, horizon):
                    continue
                kvalue = _unwrap_walrus(kvalue)
                if kkind == "plain" \
                        and isinstance(kvalue, ast.Name) \
                        and same_object(scope, kvalue.id,
                                        name, kpos, seen):
                    continue
                return True
            return False

        def identity_equiv(scope, left, right, horizon,
                           seen):
            # True when `left` and `right` provably
            # denote the same object just before
            # `horizon`: either direction of the edge
            # walk, or a common origin (live edges to
            # sources equivalent at the earlier edge,
            # with the later source unrebased between
            # the edges). Termination: horizons
            # strictly decrease and pairs are seen.
            if left == right:
                return True
            if (left, right) in seen:
                return False
            seen.add((left, right))
            seen.add((right, left))
            if same_object(scope, left, right, horizon,
                            set()) \
                    or same_object(scope, right, left,
                                   horizon, set()):
                return True

            def live_edges(name):
                out = []
                for bpos, bkind, bval in scope_binds.get(
                        id(scope), {}).get(name, []):
                    if not bpos < horizon:
                        continue
                    if bkind != "plain":
                        continue
                    bval = _unwrap_walrus(bval)
                    if not isinstance(bval, ast.Name):
                        continue
                    if edge_broken(scope, name, bpos,
                                   horizon, set()):
                        continue
                    out.append((bpos, bval.id))
                return out

            for apos, xname in live_edges(left):
                for bpos, yname in live_edges(right):
                    if apos <= bpos:
                        gap = edge_broken(
                            scope, yname, apos, bpos,
                            set())
                    else:
                        gap = edge_broken(
                            scope, xname, bpos, apos,
                            set())
                    if gap:
                        continue
                    if identity_equiv(
                            scope, xname, yname,
                            min(apos, bpos), seen):
                        return True
            return False

        def group_mates(root, node, depth, star_horizon=None,
                        skip_loops=()):
            # every group a store through root may land
            # in: the same-statement prefix (RHS effects
            # and earlier targets, replayed in order on
            # scratch groups — a store observes the
            # intermediate state), plus the window from
            # just before the enclosing statement
            # through the outermost enclosing loop end
            # (back-edges re-reach joined objects), plus
            # every component joined anywhere in an
            # enclosing loop (composed back-edges). A
            # store at depth >= 2 through a shallow-copy
            # name also reaches the source's groups from
            # the copy (copies share descendants).
            # Nested stores resolve in their own scope:
            # a shadowing local stays local (freevar
            # copies join outward), globals/nonlocals
            # and unbound names use the outer window —
            # unbounded above (call timing unknowable,
            # fail closed) and back to the enclosing
            # loop start (a def in a loop is called with
            # the current iteration's state).
            stmt = node
            nested_scope = None
            loop_end = None
            current = node
            while id(current) in parents \
                    and parents[id(current)] is not func \
                    and current is not func:
                current = parents[id(current)]
                if nested_scope is None and isinstance(
                        current, (ast.FunctionDef,
                                 ast.AsyncFunctionDef,
                                 ast.Lambda,
                                 ast.ClassDef)):
                    nested_scope = current
                elif isinstance(current, (ast.For,
                                          ast.AsyncFor,
                                          ast.While)):
                    loop_end = (current.end_lineno,
                                current.end_col_offset)
            while not isinstance(stmt, ast.stmt) \
                    and id(stmt) in parents:
                stmt = parents[id(stmt)]
            start = (stmt.lineno, stmt.col_offset)
            if nested_scope is not None:
                defpos = (nested_scope.lineno,
                          nested_scope.col_offset)
                outer_loops = [
                    span for span in loop_spans
                    if span[0] <= defpos <= span[1]]
                if outer_loops:
                    start = outer_loops[0][0]
                    for span in outer_loops[1:]:
                        if span[0] < start:
                            start = span[0]
                # a capture resolves as-of the capture
                # (binds after it cannot touch the
                # already-captured object); a real store
                # keeps the unbounded window (call
                # timing unknowable, fail closed).
                stop = star_horizon
            elif loop_end is not None:
                # a capture resolves as-of the capture
                # even inside a loop (a later pass's or
                # a later statement's rebind cannot
                # touch the already-captured object); a
                # real store keeps the loop end
                # (back-edges re-reach joined objects).
                if star_horizon is not None:
                    stop = star_horizon
                else:
                    stop = loop_end
            else:
                stop = (node.lineno, node.col_offset)
            if nested_scope is not None:
                # every nested store root resolves to
                # its binding scope first (intermediate
                # scopes and the module included) — a
                # freevar never falls straight into the
                # func window past its binder, and an
                # intermediate shadow never sees outside.
                home = home_scope_for(
                    root, nested_scope,
                    (node.lineno, node.col_offset))
                if home is not None and home is not func:
                    return nested_local_mates(
                        root, home, start, stop,
                        depth, set(),
                        (node.lineno, node.col_offset))
            mates = window_union(root, start, stop)
            prefix_copies = None
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) \
                    and nested_scope is None \
                    and any(event[:2] == start
                            for event in alias_events):
                pre = snap_at(start[0], start[1],
                              strict=True)
                scratch_g = {}
                scratch_c = {}
                if pre is not None:
                    scratch_g = {
                        name: set(members)
                        for name, members in
                        pre[0].items()}
                    scratch_c = {
                        name: set(sources)
                        for name, sources in
                        pre[1].items()}
                prefix = store_prefix_events(node, stmt)
                apply_events(prefix, scratch_g,
                             scratch_c, start)
                mates.update(scratch_g.get(root, {root}))
                prefix_copies = scratch_c.get(root, set())
            here = (node.lineno, node.col_offset)
            if any(span_start <= here <= span_end
                   for span_start, span_end, _ in loop_spans):
                mates.update(loop_union_component(
                    root, node, skip_loops))
            if depth >= 2:
                mates.update(
                    star_element_union(root, node, depth,
                                       star_horizon))
            for source, copy_pos, seed in copies_for_store(
                    root, node, depth, prefix_copies):
                mates.update(copy_source_union(
                    source, copy_pos, stop, seed))
            return mates

        def star_element_union(root, node, depth,
                               horizon=None):
            # stores through starred-target names: the
            # star binds a FRESH list, but index [i]
            # resolves to the consumed element
            # (identity) — a depth-d store applies its
            # remainder (d-1) to each consumed value
            # with that value's own semantics.
            # Consumed values ride parentless
            # synth-Tuples (real tuples never resolve
            # — they stay killed). r=1: a Name
            # resolves (the store lands in the
            # object); a copy-form stays local (its
            # top); a display stays local (a replace
            # into fresh structure). r>=2: Names
            # recurse fully; copy-forms consult their
            # sources; List/Tuple displays union plain
            # elements at r-1 (transparent indexing)
            # and Starred elements at the same level
            # (literal splicing costs no depth); Dicts
            # union plain values at r-1 and **-unpacked
            # values at the same level; anything
            # unrecognized stays local (a documented
            # miss, like unknown kills).
            # Candidates carry horizons: the root at the
            # store (or the given horizon), alias/copy
            # sources at their binding — a later rebind
            # of the candidate cannot touch the
            # already-captured list. A star bind
            # consults only while alive (no
            # non-preserving rebind of the candidate
            # reaching the horizon; same-batch
            # duplicates consult fail-closed), and an
            # alias edge expands only while live (the
            # same lifetime test — a rebind of the
            # candidate kills the path, chains
            # included).
            # Consumed names resolve as captured at the
            # unpack — never with post-unpack joins.
            # Termination: r strictly decreases per
            # star hop; within one hop the recursion is
            # structural (children only); candidate and
            # graft fixpoints range over finite
            # (name, position) pairs.
            mates = set()
            store = (node.lineno, node.col_offset)
            if horizon is None:
                horizon = store

            def shadowed(candidate, starpos, horiz):
                for _bpos, _bkind, _bval in scope_binds.get(
                        id(func), {}).get(candidate, []):
                    if not starpos < _bpos <= horiz:
                        continue
                    if not reaches(_bpos, horiz):
                        continue
                    _bval = _unwrap_walrus(_bval)
                    if _bkind != "plain":
                        return True
                    if isinstance(_bval, ast.Name) \
                            and same_object(
                                func, _bval.id, candidate,
                                _bpos, set()):
                        continue
                    if _element_preserving(_bval, candidate,
                                           _bpos):
                        # a self-copy rebinds the top but
                        # shares the elements: the star
                        # bind's provenance survives it.
                        continue
                    return True
                return False

            def _element_preserving(value, candidate, pos):
                # value denotes fresh top storage holding
                # (at least) the candidate's elements:
                # method/ctor copies, self-unpacks ([*xs],
                # (*xs,), {*xs}, extras allowed) and
                # nested unpack compositions ([*[*xs]],
                # (*(*xs,),), mixed — recursion through
                # literal displays), plus list/set/tuple/
                # frozenset of a preserving value and
                # .copy of one. Unpacks share the
                # elements (no depth cost). Fresh
                # displays, transforms and anything
                # unrecognized replace the elements (a
                # documented miss, like unknown kills).
                value = _unwrap_walrus(value)
                if value is None:
                    return False
                if candidate in _copy_source_names(
                        value, trusted_ctor):
                    return True
                if isinstance(value, (ast.List, ast.Tuple,
                                      ast.Set)):
                    for elt in value.elts:
                        if not isinstance(elt, ast.Starred):
                            continue
                        inner = _unwrap_walrus(elt.value)
                        if isinstance(inner, ast.Name):
                            if inner.id == candidate \
                                    or same_object(
                                        func, inner.id,
                                        candidate, pos,
                                        set()):
                                return True
                            continue
                        if _element_preserving(
                                inner, candidate, pos):
                            return True
                    return False
                if isinstance(value, ast.Call) \
                        and not value.keywords:
                    if isinstance(value.func, ast.Name) \
                            and value.func.id in (
                                "list", "set", "tuple",
                                "frozenset") \
                            and value.func.id not in rebound \
                            and value.func.id not in \
                            module_attr_binds \
                            and len(value.args) == 1:
                        return _element_preserving(
                            value.args[0], candidate, pos)
                    if isinstance(value.func, ast.Attribute) \
                            and value.func.attr == "copy" \
                            and not value.args:
                        return _element_preserving(
                            value.func.value, candidate,
                            pos)
                return False

            def _index_preserving(val, cand, pos):
                # strict element identity through a
                # rebind: same-object aliases and pure
                # splices ([*xs], nested, list()/
                # tuple()/.copy() of one) keep every
                # index (order and length stable);
                # extras, item transforms, dicts and
                # sets do not.
                val = _unwrap_walrus(val)
                if val is None:
                    return False
                if isinstance(val, ast.Name):
                    return same_object(
                        func, val.id, cand, pos,
                        set())
                if isinstance(val, (ast.List, ast.Tuple)):
                    if len(val.elts) != 1:
                        return False
                    only = val.elts[0]
                    if not isinstance(only, ast.Starred):
                        return False
                    inner = _unwrap_walrus(only.value)
                    if isinstance(inner, ast.Name):
                        return inner.id == cand \
                            or same_object(
                                func, inner.id, cand,
                                pos, set())
                    return _index_preserving(
                        inner, cand, pos)
                if isinstance(val, ast.Call) \
                        and not val.keywords \
                        and len(val.args) == 1:
                    if isinstance(val.func, ast.Name) \
                            and val.func.id in (
                                "list", "tuple") \
                            and val.func.id not in rebound \
                            and val.func.id not in \
                            module_attr_binds:
                        return _index_preserving(
                            val.args[0], cand, pos)
                    if isinstance(val.func,
                                  ast.Attribute) \
                            and val.func.attr == "copy" \
                            and not val.args:
                        return _index_preserving(
                            val.func.value, cand, pos)
                return False

            def _element_killed(cand, starpos, horiz,
                                consumed):
                # True when the store's statically known
                # first index into cand was replaced with
                # provably fresh storage between the star
                # bind and the horizon: the store then
                # lands in fresh storage, not in the
                # consumed element. Killed only when the
                # mapping is certain — anything
                # unrecognized keeps the consultation
                # (fail-closed): every name-rebind of
                # cand in between must preserve indices
                # (pure splices, no extras), no dels, no
                # calls mentioning cand and no
                # joined-mate subscript stores may touch
                # cand in between, and the last depth-1
                # store to the index (same-statement
                # stores disqualify — target order
                # decides) must be provably fresh and
                # reach the horizon.
                if not isinstance(node, ast.Subscript):
                    return False
                first = None
                cursor = node
                while isinstance(cursor, ast.Subscript):
                    first = cursor.slice
                    cursor = cursor.value
                if not isinstance(cursor, ast.Name) \
                        or cursor.id != cand:
                    return False

                def const_index(slc):
                    slc = _unwrap_walrus(slc)
                    if not isinstance(slc, ast.Constant):
                        return None
                    if isinstance(slc.value, bool) \
                            or not isinstance(
                                slc.value, int):
                        return None
                    return slc.value

                want = const_index(first)
                if want is None:
                    return False
                star_len = len(consumed.elts)
                starred = any(
                    isinstance(elt, ast.Starred)
                    for elt in consumed.elts)

                def norm(index):
                    if index < 0:
                        if starred:
                            return None
                        index += star_len
                    return index if index >= 0 else None

                want = norm(want)
                if want is None:
                    return False
                if home_scope_for(cand, func, starpos) \
                        is not func:
                    # a global/nonlocal candidate has
                    # out-of-scope binds: unknowable.
                    return False
                for _bpos, _bkind, _bval in scope_binds.get(
                        id(func), {}).get(cand, []):
                    if not starpos < _bpos <= horiz:
                        continue
                    if _bkind != "plain":
                        return False
                    if not _index_preserving(
                            _bval, cand, _bpos):
                        return False
                store_stmt = cursor
                probe = node
                while id(probe) in parents:
                    probe = parents[id(probe)]
                    if isinstance(probe, ast.stmt):
                        store_stmt = probe
                        break

                def nested(inner):
                    probe = inner
                    while id(probe) in parents:
                        probe = parents[id(probe)]
                        if probe is func:
                            return False
                        if isinstance(
                                probe,
                                (ast.FunctionDef,
                                 ast.AsyncFunctionDef,
                                 ast.Lambda,
                                 ast.ClassDef)):
                            return True
                    return False

                def stmt_of(inner):
                    probe = inner
                    if isinstance(probe, ast.stmt):
                        return probe
                    while id(probe) in parents:
                        probe = parents[id(probe)]
                        if isinstance(probe, ast.stmt):
                            return probe
                    return None

                def joined_mate(name, pos):
                    return name != cand and same_object(
                        func, name, cand, pos, set())

                def recv_root(node):
                    # subscript receiver root, seeing
                    # through walrus wrappers (a
                    # wrapper binds and evaluates to
                    # its value).
                    while isinstance(
                            node, ast.NamedExpr):
                        node = node.value
                    if not isinstance(node, ast.Name):
                        return None
                    return node.id

                def mutated_root(target):
                    # the root name an
                    # AugAssign/Delete target mutates,
                    # seeing through subscripts,
                    # attributes and walruses (index,
                    # slice and attribute interiors
                    # are loads, never mutations).
                    # None when the root is computed
                    # (unresolvable — fail closed).
                    node = target
                    while isinstance(
                            node,
                            (ast.Subscript,
                             ast.Attribute,
                             ast.NamedExpr)):
                        node = node.value
                    if not isinstance(node, ast.Name):
                        return None
                    return node.id

                repl = []
                for item in ast.walk(func):
                    if not hasattr(item, "lineno") \
                            or not hasattr(
                                item, "col_offset"):
                        continue
                    ipos = (item.lineno, item.col_offset)
                    if not starpos < ipos <= horiz:
                        continue
                    if isinstance(
                            item,
                            (ast.Assign, ast.AnnAssign)):
                        stored = item.value
                        if stored is None:
                            continue
                        targets = item.targets \
                            if isinstance(
                                item, ast.Assign) \
                            else [item.target]
                        for tidx, target in enumerate(
                                targets):
                            for leaf, val in _walk_pairs(
                                    target, stored):
                                if not isinstance(
                                        leaf,
                                        ast.Subscript):
                                    continue
                                root = recv_root(leaf.value)
                                if root is None:
                                    continue
                                if root == cand:
                                    if nested(item) \
                                            or stmt_of(
                                                item) is \
                                            store_stmt:
                                        return False
                                    if isinstance(
                                            _unwrap_walrus(
                                                leaf.slice),
                                            ast.Slice):
                                        # a slice store
                                        # shifts indices —
                                        # the mapping is
                                        # gone.
                                        return False
                                    got = const_index(
                                        leaf.slice)
                                    got = norm(got) \
                                        if got is not None \
                                        else None
                                    if got is None:
                                        if not _fresh_value(
                                                val,
                                                trusted_ctor):
                                            return False
                                        continue
                                    if got == want:
                                        repl.append(
                                            (ipos, tidx,
                                             val))
                                elif joined_mate(
                                        root, ipos):
                                    return False
                    elif isinstance(item, ast.AugAssign):
                        root = mutated_root(item.target)
                        if root is None \
                                or root == cand \
                                or joined_mate(root, ipos):
                            return False
                    elif isinstance(item, ast.Delete):
                        for gone in item.targets:
                            root = mutated_root(gone)
                            if root is None \
                                    or root == cand \
                                    or joined_mate(
                                        root, ipos):
                                return False
                    elif isinstance(item, ast.Call):
                        mentions = False
                        for part in list(item.args) \
                                + [keyword.value
                                   for keyword in
                                   item.keywords] \
                                + [item.func]:
                            for loaded in ast.walk(part):
                                if not isinstance(
                                        loaded, ast.Name) \
                                        or not isinstance(
                                            loaded.ctx,
                                            ast.Load):
                                    continue
                                if loaded.id == cand \
                                        or joined_mate(
                                            loaded.id,
                                            ipos):
                                    mentions = True
                                    break
                            if mentions:
                                break
                        if mentions:
                            return False
                    if nested(item):
                        # a nested write to the name may
                        # touch the func binding through
                        # a closure (timing unknowable) —
                        # a nested read never mutates.
                        if isinstance(item, ast.Name) \
                                and isinstance(
                                    item.ctx, ast.Store) \
                                and item.id == cand:
                            return False
                        if isinstance(item, ast.arg) \
                                and item.arg == cand:
                            return False
                        if isinstance(
                                item,
                                ast.ExceptHandler) \
                                and item.name == cand:
                            return False
                        if isinstance(
                                item, ast.alias) \
                                and (item.asname == cand
                                     or item.name.split(
                                         ".")[0] == cand):
                            return False
                        if isinstance(
                                item,
                                (ast.FunctionDef,
                                 ast.AsyncFunctionDef,
                                 ast.ClassDef)) \
                                and item.name == cand:
                            return False
                        if isinstance(item, ast.pattern) \
                                and cand in _match_names(
                                    item):
                            return False
                storepos = (node.lineno, node.col_offset)

                def replacement_runs(assign):
                    # the replacement runs whenever the
                    # tainted store does: same-region
                    # pairs co-execute (both-or-neither
                    # is fine — moot stores stay silent),
                    # crossings need proofs (constant
                    # folds, proven first passes, first
                    # statements), and exits before the
                    # replacement invalidate.
                    rpos = (assign.lineno, assign.col_offset)
                    child = assign
                    probe = assign
                    try_nodes_local = (ast.Try, ast.TryStar) \
                        if hasattr(ast, "TryStar") \
                        else (ast.Try,)
                    while id(probe) in parents:
                        probe = parents[id(probe)]
                        if probe is func:
                            break
                        if isinstance(probe, ast.If):
                            branch = probe.body \
                                if child in probe.body \
                                else probe.orelse
                            if any((sub.lineno,
                                    sub.col_offset)
                                   <= storepos
                                   <= (sub.end_lineno,
                                       sub.end_col_offset)
                                   for sub in branch):
                                pass
                            else:
                                test = _unwrap_walrus(
                                    probe.test)
                                val = test.value \
                                    if isinstance(
                                        test, ast.Constant) \
                                    else None
                                if child in probe.body:
                                    if val is not True:
                                        return False
                                elif val is not False:
                                    return False
                        elif isinstance(
                                probe,
                                (ast.For, ast.AsyncFor,
                                 ast.While)):
                            child_in_body = \
                                child in probe.body
                            pub_in_body = any(
                                (sub.lineno,
                                 sub.col_offset)
                                <= storepos
                                <= (sub.end_lineno,
                                    sub.end_col_offset)
                                for sub in probe.body)
                            if child_in_body and pub_in_body:
                                pass
                            elif not child_in_body:
                                return False
                            elif isinstance(
                                    probe,
                                    (ast.For, ast.AsyncFor)):
                                itr = _unwrap_walrus(
                                    probe.iter)
                                if isinstance(
                                        itr,
                                        (ast.List,
                                         ast.Tuple,
                                         ast.Set)):
                                    if not any(
                                            not isinstance(
                                                elt,
                                                ast.Starred)
                                            for elt in
                                            itr.elts):
                                        return False
                                elif isinstance(
                                        itr, ast.Dict):
                                    if not any(
                                            key is not None
                                            for key in
                                            itr.keys):
                                        return False
                                elif isinstance(
                                        itr, ast.Constant) \
                                        and isinstance(
                                            itr.value,
                                            (str, bytes)):
                                    if not itr.value:
                                        return False
                                else:
                                    return False
                            else:
                                test = _unwrap_walrus(
                                    probe.test)
                                if not isinstance(
                                        test, ast.Constant) \
                                        or test.value \
                                        is not True:
                                    return False
                        elif isinstance(probe, ast.Match):
                            # the child here is the
                            # match_case node itself —
                            # preserve its body region
                            # (co-executing replacements
                            # in the same case body
                            # prove; crossings do not).
                            if child not in probe.cases:
                                return False
                            if not any(
                                    (sub.lineno,
                                     sub.col_offset)
                                    <= storepos
                                    <= (sub.end_lineno,
                                        sub.end_col_offset)
                                    for sub in child.body):
                                return False
                        elif isinstance(
                                probe, try_nodes_local):
                            # each handler is its own
                            # region (sibling handlers
                            # never co-execute — a
                            # replacement in one proves
                            # nothing about a store in
                            # another).
                            regions = [probe.body,
                                       probe.orelse,
                                       probe.finalbody]
                            mine = None
                            for region in regions:
                                if child in region:
                                    mine = region
                                    break
                            if mine is None:
                                for handler in \
                                        probe.handlers:
                                    if child is handler:
                                        mine = handler.body
                                        break
                            if mine is None:
                                return False
                            same = any(
                                (sub.lineno,
                                 sub.col_offset)
                                <= storepos
                                <= (sub.end_lineno,
                                    sub.end_col_offset)
                                for sub in mine)
                            if same:
                                pass
                            elif mine is probe.orelse:
                                return False
                            elif mine is probe.body:
                                # the body completed (the
                                # else runs) or the store
                                # sits past a first
                                # statement (handler/
                                # finally observe it).
                                if not any(
                                        (sub.lineno,
                                         sub.col_offset)
                                        <= storepos
                                        <= (sub.end_lineno,
                                            sub.end_col_offset)
                                        for sub in
                                        probe.orelse):
                                    first = [
                                        sub for sub in
                                        probe.body
                                        if isinstance(
                                            sub, ast.stmt)]
                                    if not first \
                                            or first[0] \
                                            is not child:
                                        return False
                            elif mine is probe.finalbody:
                                pass
                            else:
                                return False
                        child = probe
                    # exits before the replacement at any
                    # ancestor level skip it (definite
                    # compound exits and provable
                    # constant raises included — an
                    # exception suppressed downstream
                    # still skips the replacement while
                    # the store resumes).
                    child = assign
                    probe = assign
                    while id(probe) in parents:
                        probe = parents[id(probe)]
                        if probe is func:
                            break
                        for field in ("body", "orelse",
                                      "finalbody"):
                            seq = getattr(
                                probe, field, None)
                            if not isinstance(
                                    seq, list) \
                                    or child not in seq:
                                continue
                            for stmt in seq:
                                if stmt is child:
                                    break
                                if not _stmt_may_fall(
                                        stmt, False):
                                    return False
                        child = probe
                    return True

                if not repl:
                    return False
                groups = {}
                for _rpos, _tidx, _rval in repl:
                    groups.setdefault(
                        (_rpos, _tidx), []).append(_rval)
                rpos, _ = max(groups)
                if not all(_fresh_value(_v, trusted_ctor)
                           for _v in groups[(rpos, _)]):
                    # the last group wins; duplicate
                    # leaves pair ambiguously, so a
                    # non-fresh contender declines
                    # (an all-fresh group kills
                    # regardless of pairing).
                    return False
                # the winning replacement statement.
                rnode = None
                for item in ast.walk(func):
                    if not hasattr(item, "lineno"):
                        continue
                    if (item.lineno, item.col_offset) \
                            == rpos \
                            and isinstance(
                                item,
                                (ast.Assign,
                                 ast.AnnAssign)):
                        rnode = item
                        break
                return rnode is not None \
                    and replacement_runs(rnode)

            _seen_displays = set()

            def resolve(value, level, capos):
                value = _unwrap_walrus(value)
                if isinstance(value, ast.Name):
                    mates.update(
                        captured_union(value.id, capos,
                                       level, horizon))
                    # a name bound to a display routes
                    # the display structurally (an alias
                    # costs no depth): the contained
                    # values are the name's values as of
                    # the query time. (name, level, time)
                    # bounds alias cycles (the same name
                    # denotes different displays at
                    # different binding horizons).
                    if (value.id, level, capos) not in \
                            _seen_displays:
                        _seen_displays.add((value.id,
                                            level, capos))
                        for disp, dpos in \
                                name_display_binds(
                                    value.id, capos, func):
                            resolve(disp, level, dpos)
                    return
                if isinstance(value, ast.Starred):
                    resolve(value.value, level, capos)
                    return
                if level < 2:
                    return
                disp = _copy_display_operand(value,
                                             trusted_ctor)
                if disp is not None:
                    # a copy shares the operand display's
                    # values/elements at the same depth —
                    # resolve it structurally (explicit
                    # values and unpacks alike).
                    resolve(disp, level, capos)
                    return
                # dicts always resolve structurally: a
                # mixed display ({**source, "k": v})
                # unions the unpacked mapping AND the
                # explicit values (the sources shortcut
                # would drop the explicit ones).
                sources = () if isinstance(
                    value, ast.Dict) else _copy_source_names(
                    value, trusted_ctor)
                if sources:
                    for source in sources:
                        mates.update(
                            captured_union(source, capos,
                                           level, horizon))
                        if (source, level, capos) \
                                not in _seen_displays:
                            _seen_displays.add((source,
                                                level,
                                                capos))
                            for disp, dpos in \
                                    name_display_binds(
                                        source, capos,
                                        func):
                                resolve(disp, level, dpos)
                    return
                if isinstance(value, (ast.List, ast.Tuple,
                                        ast.Set)):
                    # literal * splicing is transparent
                    # to indexing depth (one subscript
                    # traverses the splice and the
                    # index together); set elements
                    # route like sequence elements (a
                    # converted set's elements are the
                    # source's).
                    for elt in value.elts:
                        if isinstance(elt, ast.Starred):
                            resolve(elt, level, capos)
                        else:
                            resolve(elt, level - 1, capos)
                    return
                if isinstance(value, ast.Dict):
                    # same for ** unpacking (plain values
                    # still cost their index level).
                    for key, val in zip(value.keys,
                                        value.values):
                        if key is None:
                            resolve(val, level, capos)
                        else:
                            resolve(val, level - 1, capos)
                    return
                # Set, Constant, and anything
                # unrecognized stay local.

            seen_c = set()
            queue = [(root, horizon)]
            cands = []
            while queue:
                cand, horiz = queue.pop()
                if (cand, horiz) in seen_c:
                    continue
                seen_c.add((cand, horiz))
                cands.append((cand, horiz))
                for _bpos, _bkind, _bval in scope_binds.get(
                        id(func), {}).get(cand, []):
                    if _bkind != "plain" or _bpos > horiz:
                        continue
                    _bval = _unwrap_walrus(_bval)
                    if isinstance(_bval, ast.Name):
                        # the edge is live only while the
                        # alias still denotes the source
                        # (a later rebind of the
                        # candidate kills the path, like
                        # any star bind).
                        if shadowed(cand, _bpos, horiz):
                            continue
                        queue.append((_bval.id, _bpos))
                for _src, _cpos, _seed in copies_at(
                        cand, horiz[0], horiz[1]):
                    queue.append((_src, _cpos))
            for cand, horiz in cands:
                for _pos, kind, value in scope_binds.get(
                        id(func), {}).get(cand, []):
                    if kind != "plain" or value is None:
                        continue
                    if not isinstance(value, ast.Tuple):
                        continue
                    if id(value) in parents:
                        continue
                    if _pos > horiz:
                        continue
                    if shadowed(cand, _pos, horiz):
                        continue
                    if cand == root and _element_killed(
                            cand, _pos, horiz, value):
                        continue
                    for consumed in value.elts:
                        resolve(consumed, depth - 1, _pos)
            return mates

        def captured_union(name, capos, level, prune_hi):
            # names sharing the object `name` denoted at
            # capos (a star-capture time): the
            # binding-time window at the unpack (stops
            # exclude post-capture rebinds), loop unions
            # only for loops whose body does not rebind
            # the name before the capture
            # (pass-invariant captures skip them — the
            # reset rebind runs every pass AND its
            # value is pass-invariant: fresh, or a
            # name the loop never re-points to
            # non-fresh storage), plus
            # post-capture aliases (any level) and
            # copies (level >= 2) gated on no
            # intervening non-preserving rebind. The
            # skip test and the graft consult the
            # name's home scope at the capture (an
            # unrelated same-spelled bind in another
            # scope neither skips nor grafts); unbound
            # names approximate with func binds. A mate
            # rebased between the capture and the prune
            # horizon (the store, or the outer capture
            # for chains) no longer denotes the captured
            # object and is dropped — but only on a
            # reaching last bind with a provably
            # non-captured value (conditional binds,
            # restores through surviving mates, and
            # unknown values keep, fail-closed).
            unpack = None
            for stmt in ast.walk(func):
                if isinstance(stmt, ast.stmt) \
                        and (stmt.lineno,
                             stmt.col_offset) == capos:
                    unpack = stmt
                    break
            if unpack is None:
                # unreachable for star binds (their capos
                # is always an Assign position in this
                # subtree) — fail-safe bare spelling.
                return {name}
            scope = func
            cursor = unpack
            while id(cursor) in parents:
                cursor = parents[id(cursor)]
                if cursor is func:
                    break
                if isinstance(cursor, (ast.FunctionDef,
                                       ast.AsyncFunctionDef,
                                       ast.Lambda,
                                       ast.ClassDef)):
                    scope = cursor
                    break
            home = home_scope_for(name, scope, capos)
            if home is not None:
                homebinds = scope_binds.get(id(home), {})
            else:
                homebinds = scope_binds.get(id(func), {})
            def _pass_invariant(value, span_start,
                                span_end):
                # the reset assigns the same object (or a
                # fresh one) on every pass: load-free
                # values qualify, as do names no bind
                # inside the span re-points to
                # non-fresh storage (a name rebound to
                # shared state mid-loop captures a
                # different object per pass — a reaching
                # assignment alone proves nothing).
                value = _unwrap_walrus(value)
                if value is None:
                    return False
                if _fresh_value(value, trusted_ctor):
                    return True
                if not isinstance(value, ast.Name):
                    return False
                for table in (homebinds,
                              scope_binds.get(id(tree), {})):
                    for _bpos, _bkind, _bval in table.get(
                            value.id, []):
                        if not span_start < _bpos \
                                <= span_end:
                            continue
                        if _bkind != "plain" \
                                or not _fresh_value(
                                    _unwrap_walrus(_bval),
                                    trusted_ctor):
                            return False
                return True

            skip = set()
            for span_start, span_end, loop in loop_spans:
                if not span_start <= capos <= span_end:
                    continue
                # the capture reads whatever the loop
                # leaves in `name`: skip only with an
                # unconditional pre-capture reset (it
                # runs every pass, overwriting feedback
                # and pre-loop state) AND the surviving
                # reset plus every later pre-capture
                # definition invariant (definitions
                # before the last unconditional reset
                # are overwritten on every pass, so
                # they never matter; a conditional
                # override after it may still inject
                # garbage — post-capture binds are
                # always overwritten, so they never
                # matter).
                resets = [
                    (_bpos, _bkind, _bval)
                    for _bpos, _bkind, _bval in homebinds.get(
                        name, [])
                    if span_start < _bpos < capos]
                unconditional = [
                    _bpos
                    for _bpos, _bkind, _bval in resets
                    if _bkind == "plain"
                    and reaches(_bpos, capos)]
                if not unconditional:
                    continue
                last_reset = max(unconditional)
                if all(
                        _bkind == "plain"
                        and _pass_invariant(
                            _bval, span_start, span_end)
                        for _bpos, _bkind, _bval in resets
                        if _bpos >= last_reset):
                    skip.add(id(loop))
            mates = set(group_mates(
                name, unpack, level, star_horizon=capos,
                skip_loops=skip))

            def rebased(src, lo, hi):
                # src denotes other than captured at hi:
                # walk its binds in (lo, hi) in order —
                # liveness starts joined and each
                # reaching bind re-decides it (an alias
                # of, or at depth >= 2 a copy sharing,
                # a name live then rejoins; anything
                # else breaks, and a break stands until
                # a later bind restores). Same-position
                # binds postdate the edge (same-batch
                # RHS values pre-date their stores).
                # The identity alternative is
                # capture-anchored: same_object answers
                # at-horizon, so it rejoins only while
                # the root itself still denotes the
                # captured object (a restore through a
                # rebound-away spelling restores
                # nothing). Liveness is possible
                # provenance: a restore rejoins whether
                # definite or conditional (its source
                # must be live then), while only a
                # definite non-restoring bind breaks (a
                # conditional break keeps the prior
                # state). Termination: nested horizons
                # strictly decrease.
                live = True
                ordered = sorted(
                    homebinds.get(src, []),
                    key=lambda bind: bind[0])
                for _bpos, _bkind, _bval in ordered:
                    if not lo < _bpos < hi:
                        continue
                    _bval = _unwrap_walrus(_bval)
                    if _bkind == "plain" \
                            and isinstance(
                                _bval, ast.Name) \
                            and (restored(_bval.id, _bpos)
                                 or (not rebased(
                                         name, capos, _bpos)
                                     and same_object(
                                         home if home is not
                                         None
                                         else func, _bval.id,
                                         name, _bpos,
                                         set()))):
                        live = True
                        continue
                    if _bkind == "plain" \
                            and level >= 2 \
                            and _bval is not None \
                            and any(
                                restored(s, _bpos)
                                for s in _copy_source_names(
                                    _bval, trusted_ctor)):
                        live = True
                        continue
                    if reaches(_bpos, hi):
                        live = False
                return not live

            def restored(other, when):
                return other in graft_seen \
                    and graft_pos[other] <= when \
                    and not rebased(
                        other, graft_pos[other], when)

            graft_seen = {name}
            graft_pos = {name: capos}
            graft_queue = [(name, capos)]
            for peer in sorted(mates):
                # a capture-window peer denoting the
                # root at capture seeds the graft
                # (post-capture aliases of the peer
                # observe captured structure).
                # Identity is equivalence: either
                # edge direction, or a common origin
                # (peers aliased to the same source
                # before their own rebases).
                if peer != name \
                        and peer not in graft_seen \
                        and identity_equiv(
                            home if home is not None
                            else func, peer, name, capos,
                            set()):
                    graft_seen.add(peer)
                    graft_pos[peer] = capos
                    graft_queue.append((peer, capos))
            while graft_queue:
                src, src_lo = graft_queue.pop()
                for other, binds in homebinds.items():
                    for _bpos, _bkind, _bval in binds:
                        if _bpos <= capos \
                                or _bkind != "plain":
                            continue
                        if other in graft_seen:
                            continue
                        _bval = _unwrap_walrus(_bval)
                        is_alias = isinstance(
                            _bval, ast.Name) \
                            and _bval.id == src
                        is_copy = level >= 2 and src in \
                            _copy_source_names(
                                _bval, trusted_ctor)
                        if not (is_alias or is_copy):
                            continue
                        # the edge reads src at the graft:
                        # only a reaching non-preserving
                        # rebind since src's own
                        # installation (the capture for
                        # the root) breaks it — the
                        # installation itself and
                        # conditional rebinds never do.
                        if rebased(src, src_lo, _bpos):
                            continue
                        graft_seen.add(other)
                        graft_pos[other] = _bpos
                        graft_queue.append((other, _bpos))
            mates.update(graft_seen)
            # ever-joined membership: a restore keeps
            # when its source denoted captured at the
            # restoration (not rebased between its
            # installation and the restore) — pruning
            # the source later cannot retro-kill the
            # already-captured value.
            ever = set(mates)
            if prune_hi is not None:
                # drop mates the prune horizon observes
                # rebased (iterate to a fixpoint).
                changed = True
                while changed:
                    changed = False
                    for mate in list(mates):
                        # a grafted mate is rebased only
                        # by binds after its own
                        # installation (a later rebind of
                        # the name it was grafted from
                        # cannot touch it); window mates
                        # count from the capture.
                        installed = graft_pos.get(
                            mate, capos)
                        late = [
                            (_bpos, _bkind, _bval)
                            for _bpos, _bkind, _bval
                            in homebinds.get(mate, [])
                            if installed < _bpos
                            <= prune_hi]
                        if not late:
                            continue
                        # the last bind decides (a stable
                        # sort keeps note order, so a
                        # same-batch duplicate resolves
                        # to the last-noted target) — replayed
                        # over conditional tails: a restoring
                        # bind rejoins whether definite or
                        # conditional, a definite
                        # non-restoring bind breaks, and a
                        # conditional non-restoring bind
                        # restores nothing (drop it and
                        # re-decide from the earlier binds;
                        # if none remain, the mate was never
                        # definitely broken — keep).
                        late.sort(key=lambda triple: triple[0])
                        while late:
                            _lpos, _lkind, _lval = late[-1]
                            _lval = _unwrap_walrus(_lval)
                            if _lkind == "plain" \
                                    and isinstance(
                                        _lval, ast.Name) \
                                    and _lval.id in ever \
                                    and not rebased(
                                        _lval.id,
                                        graft_pos.get(
                                            _lval.id, capos),
                                        _lpos):
                                break
                            if _lkind == "plain" \
                                    and level >= 2 \
                                    and _lval is not None \
                                    and any(
                                        src in ever
                                        and not rebased(
                                            src,
                                            graft_pos.get(
                                                src, capos),
                                            _lpos)
                                        for src in
                                        _copy_source_names(
                                            _lval,
                                            trusted_ctor)):
                                # a copy shares its source's
                                # descendants: at depth >= 2
                                # the rebased mate still
                                # observes captured structure
                                # when the source denotes
                                # captured at the copy (at
                                # depth 1 the copy's top is
                                # unrelated, so killing there
                                # stays exact) — keep.
                                break
                            if _lkind == "def":
                                # a bare def or a baseless,
                                # keywordless class binds
                                # provably fresh storage; a
                                # decorated def or a keyworded
                                # or based class may hand the
                                # old object back — keep.
                                if getattr(
                                        _lval,
                                        "decorator_list",
                                        []):
                                    break
                                if isinstance(
                                        _lval, ast.ClassDef) \
                                        and (_lval.keywords
                                             or _lval.bases):
                                    break
                            elif _lval is None or not (
                                    _fresh_value(
                                        _lval, trusted_ctor)
                                    or _copy_source_names(
                                        _lval, trusted_ctor)
                                    or isinstance(
                                        _lval, ast.Name)):
                                # a valueless bind or an
                                # unknown value (a call, an
                                # attribute, a subscript, an
                                # augmented store...): may
                                # flow the captured object
                                # back — keep.
                                break
                            if not reaches(_lpos, prune_hi):
                                late = late[:-1]
                                continue
                            mates.discard(mate)
                            changed = True
                            break
            return mates

        def catches_name_error(nodetype):
            # whether an except handler can
            # catch the del's NameError: bare
            # always; tuples, starred and PEP
            # 604 unions by members; names in
            # the NameError-superclass chain
            # (NameError, Exception,
            # BaseException — LookupError is
            # NOT one: issubclass is False)
            # (bare or builtins-dotted) yes;
            # other unrebound builtin
            # exceptions no (a builtins attribute
            # rebind voids identity too);
            # anything else yes — aliasing is
            # unknowable, fail closed.
            if nodetype is None:
                return True
            if isinstance(nodetype, ast.Tuple):
                return any(
                    catches_name_error(elt)
                    for elt in nodetype.elts)
            if isinstance(nodetype, ast.Starred):
                return catches_name_error(
                    nodetype.value)
            if isinstance(nodetype, ast.BinOp) \
                    and isinstance(
                        nodetype.op, ast.BitOr):
                return catches_name_error(
                    nodetype.left) \
                    or catches_name_error(
                        nodetype.right)
            catching = ("NameError",
                        "Exception",
                        "BaseException")
            if isinstance(nodetype, ast.Name):
                spelling = nodetype.id
            elif isinstance(nodetype,
                            ast.Attribute) \
                    and isinstance(
                        nodetype.value,
                        ast.Name) \
                    and nodetype.value.id == \
                    "builtins" \
                    and "builtins" not in \
                    rebound:
                spelling = nodetype.attr
            else:
                return True
            if spelling in catching:
                return True
            builtin = getattr(
                builtins, spelling, None)
            if isinstance(builtin, type) \
                    and issubclass(
                        builtin, BaseException) \
                    and spelling not in rebound \
                    and spelling not in \
                    builtins_attr_binds:
                return False
            return True

        _publish_dead_memo = {}

        def publish_dead(func, call):
            # a publish downstream of a raising
            # class-body del that no catcher saves is
            # dead (moot): the exception propagates
            # past it, so nothing escapes there. A
            # catcher saves it only when the publish
            # sits past the try (or in its handlers /
            # finally) — a publish inside the catching
            # body after the raise is skipped. A
            # publish in the finally of a try holding
            # the del runs before propagation, so it
            # is live. Only provably-raising dels
            # count: binding/deletion state replays in
            # order (a bind installs, a del removes;
            # conditional events leave Unknown — only
            # definitely-absent raises), the del must
            # reach the publish (a skipped del kills
            # nothing), and a metaclass keyword voids
            # the must-raise assumption (__prepare__
            # may supply the name). Nested functions
            # are pruned (unknowable calls fail
            # closed = live).
            key = (id(func), call.lineno, call.col_offset)
            if key in _publish_dead_memo:
                return _publish_dead_memo[key]
            ppos = (call.lineno, call.col_offset)
            try_nodes = (ast.Try,)
            trystar = getattr(ast, "TryStar", None)
            if trystar is not None:
                try_nodes += (trystar,)
            raises = []
            trys = []
            stack = list(func.body)
            while stack:
                node = stack.pop()
                if isinstance(node, (ast.FunctionDef,
                                     ast.AsyncFunctionDef,
                                     ast.Lambda)):
                    continue
                if isinstance(node, ast.Delete):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            raises.append(
                                ((node.lineno,
                                  node.col_offset),
                                 target.id, node))
                if isinstance(node, try_nodes):
                    trys.append(node)
                stack.extend(ast.iter_child_nodes(node))
            def executes(dnode):
                # the del provably runs (rather than
                # skipped or dead): every enclosing
                # branch definite — straight-line,
                # with-bodies, same-region try parts,
                # same-pass loop bodies (a pass
                # running both orders them; a pass
                # running only the publish is moot),
                # loops with a proven first pass when
                # the publish sits outside, and
                # constant-folded if arms (same-branch
                # publishes are dead-or-moot) — and no
                # in-block exit (return/raise/break/
                # continue/assert) before it.
                child = dnode
                probe = dnode
                while id(probe) in parents:
                    probe = parents[id(probe)]
                    if probe is func:
                        break
                    if isinstance(probe, ast.If):
                        branch = probe.body \
                            if child in probe.body \
                            else probe.orelse
                        if any((sub.lineno,
                                sub.col_offset)
                               <= ppos
                               <= (sub.end_lineno,
                                   sub.end_col_offset)
                               for sub in branch):
                            pass
                        else:
                            test = _unwrap_walrus(
                                probe.test)
                            val = test.value \
                                if isinstance(
                                    test, ast.Constant) \
                                else None
                            if child in probe.body:
                                if val is not True:
                                    return False
                            elif val is not False:
                                return False
                    elif isinstance(
                            probe,
                            (ast.For, ast.AsyncFor,
                             ast.While)):
                        # body and else are distinct
                        # regions: same-body publishes
                        # share the pass; else and
                        # outside publishes need a proven
                        # first pass (an empty loop skips
                        # the body and runs the else).
                        # Only provably-nonempty
                        # iterators prove it (splats and
                        # unpacks are unknowable).
                        child_in_body = \
                            child in probe.body
                        pub_in_body = any(
                            (sub.lineno, sub.col_offset)
                            <= ppos
                            <= (sub.end_lineno,
                                sub.end_col_offset)
                            for sub in probe.body)
                        if child_in_body and pub_in_body:
                            pass
                        elif not child_in_body:
                            return False
                        elif isinstance(
                                probe,
                                (ast.For, ast.AsyncFor)):
                            itr = _unwrap_walrus(
                                probe.iter)
                            if isinstance(
                                    itr,
                                    (ast.List, ast.Tuple,
                                     ast.Set)):
                                if not any(
                                        not isinstance(
                                            elt,
                                            ast.Starred)
                                        for elt in
                                        itr.elts):
                                    return False
                            elif isinstance(
                                    itr, ast.Dict):
                                if not any(
                                        key is not None
                                        for key in
                                        itr.keys):
                                    return False
                            elif isinstance(
                                    itr, ast.Constant) \
                                    and isinstance(
                                        itr.value,
                                        (str, bytes)):
                                if not itr.value:
                                    return False
                            else:
                                return False
                        else:
                            test = _unwrap_walrus(
                                probe.test)
                            if not isinstance(
                                    test, ast.Constant) \
                                    or test.value \
                                    is not True:
                                return False
                    elif isinstance(probe, ast.Match):
                        return False
                    elif isinstance(probe, try_nodes):
                        regions = [probe.body,
                                   probe.handlers,
                                   probe.orelse,
                                   probe.finalbody]
                        same = False
                        for region in regions:
                            if not any(
                                    sub is child
                                    for sub in region):
                                continue
                            if any(
                                    (sub.lineno,
                                     sub.col_offset)
                                    <= ppos
                                    <= (sub.end_lineno,
                                        sub.end_col_offset)
                                    for sub in region):
                                same = True
                            break
                        if not same \
                                and child not in \
                                probe.body \
                                and child not in \
                                probe.finalbody:
                            return False
                    child = probe
                # exits before the del at any ancestor
                # level (an exit runs first and skips the
                # rest of its block, including the del's
                # subtree; handlers and cases are
                # alternatives, not sequences, so only
                # their bodies scan).
                child = dnode
                probe = dnode
                while id(probe) in parents:
                    probe = parents[id(probe)]
                    if probe is func:
                        break
                    for field in ("body", "orelse",
                                  "finalbody"):
                        seq = getattr(probe, field, None)
                        if not isinstance(seq, list) \
                                or child not in seq:
                            continue
                        for stmt in seq:
                            if stmt is child:
                                break
                            if not _stmt_may_fall(
                                    stmt, False):
                                return False
                    child = probe
                return True

            dead = False
            for rpos, name, dnode in raises:
                if not rpos < ppos:
                    continue
                if not executes(dnode):
                    continue
                home = None
                cursor = dnode
                while id(cursor) in parents:
                    cursor = parents[id(cursor)]
                    if isinstance(cursor, ast.ClassDef):
                        home = cursor
                        break
                    if cursor is func or isinstance(
                            cursor, (ast.FunctionDef,
                                     ast.AsyncFunctionDef,
                                     ast.Lambda)):
                        break
                if home is None:
                    continue
                if home.keywords:
                    continue

                def default_namespace(cls, seen):
                    # the class builds a default
                    # namespace: no metaclass keywords
                    # and every base a locally defined
                    # class with a default namespace
                    # (transitively — an inherited
                    # metaclass __prepare__ may supply
                    # names) or unrebound object.
                    # Anything else voids the proof. The
                    # base proves by CURRENT identity: a
                    # single ancestral def, still
                    # denoting it (no rebind between the
                    # def and the class), undecorated (a
                    # decorator may replace the base).
                    # Cycle detection is path-based (an
                    # ancestor revisited), not
                    # visit-based: a default diamond
                    # revisits its common ancestor
                    # across siblings, which proves
                    # again rather than voiding.
                    if id(cls) in seen:
                        return False
                    seen = seen | {id(cls)}
                    for base in cls.bases:
                        base = _unwrap_walrus(base)
                        if not isinstance(
                                base, ast.Name):
                            return False
                        if base.id == "object" \
                                and "object" not in rebound \
                                and "object" not in \
                                builtins_attr_binds:
                            continue
                        # bases evaluate in the scope
                        # enclosing the class def — an
                        # outer class body, not the
                        # function (a class-namespace
                        # shadow wins there).
                        enclosing = func
                        cursor = cls
                        while id(cursor) in parents:
                            cursor = parents[id(cursor)]
                            if isinstance(
                                    cursor,
                                    (ast.FunctionDef,
                                     ast.AsyncFunctionDef,
                                     ast.Lambda,
                                     ast.ClassDef)):
                                enclosing = cursor
                                break
                            if cursor is tree:
                                enclosing = tree
                                break
                        bhome = home_scope_for(
                            base.id, enclosing,
                            (cls.lineno, cls.col_offset))
                        if bhome is None:
                            return False
                        found = [
                            (_bpos, bval)
                            for _bpos, bkind, bval in
                            scope_binds.get(
                                id(bhome), {}).get(
                                    base.id, [])
                            if bkind == "def"
                            and isinstance(
                                bval, ast.ClassDef)
                            and _bpos < (cls.lineno,
                                         cls.col_offset)]
                        if len(found) != 1:
                            return False
                        defpos, target = found[0]
                        if target.keywords:
                            return False
                        if target.decorator_list:
                            return False
                        if any(defpos < _bpos < (cls.lineno,
                                                 cls.col_offset)
                               for _bpos, _, _ in
                               scope_binds.get(
                                   id(bhome), {}).get(
                                       base.id, [])):
                            return False
                        if not default_namespace(
                                target, seen):
                            return False
                    return True

                if not default_namespace(home, set()):
                    continue
                cursor = dnode
                suppressed = False
                while id(cursor) in parents:
                    cursor = parents[id(cursor)]
                    if cursor is func \
                            or not isinstance(
                                cursor,
                                (ast.With, ast.AsyncWith)):
                        if cursor is func:
                            break
                        continue
                    if ppos > (cursor.end_lineno,
                               cursor.end_col_offset):
                        suppressed = True
                        break
                if suppressed:
                    continue
                events = [
                    (bpos, True)
                    for bpos, _, _ in scope_binds.get(
                        id(home), {}).get(name, [])
                    if bpos < rpos]
                # class-level dels only (nested
                # scopes bind and delete locally).
                delstack = [home]
                while delstack:
                    top = delstack.pop()
                    for sub in ast.iter_child_nodes(top):
                        if isinstance(
                                sub,
                                (ast.FunctionDef,
                                 ast.AsyncFunctionDef,
                                 ast.Lambda,
                                 ast.ClassDef)):
                            continue
                        if isinstance(sub, ast.Delete):
                            for target in sub.targets:
                                if isinstance(
                                        target,
                                        ast.Name) \
                                        and target.id \
                                        == name:
                                    dpos = (
                                        target.lineno,
                                        target.col_offset)
                                    if dpos < rpos:
                                        events.append(
                                            (dpos, False))
                        delstack.append(sub)
                present = name in ("__module__",
                                     "__qualname__") \
                    or (name == "__doc__"
                        and home.body
                        and isinstance(home.body[0],
                                       ast.Expr)
                        and isinstance(home.body[0].value,
                                       ast.Constant)
                        and isinstance(
                            home.body[0].value.value,
                            str)) \
                    or (name == "__firstlineno__"
                        and sys.version_info >= (3, 14)) \
                    or (name == "__annotations__"
                        and sys.version_info < (3, 14)
                        and _class_annotated(home))
                unknown = False
                for epos, is_bind in sorted(events):
                    definite = reaches(epos, rpos)
                    if is_bind:
                        if definite:
                            present = True
                            unknown = False
                        else:
                            unknown = True
                    elif present and not unknown:
                        if definite:
                            present = False
                        else:
                            unknown = True
                    elif not present and not unknown:
                        pass
                    else:
                        unknown = True
                if unknown or present:
                    continue
                finally_live = False
                for trobj in trys:
                    tspan = ((trobj.lineno, trobj.col_offset),
                             (trobj.end_lineno,
                              trobj.end_col_offset))
                    if not tspan[0] <= rpos <= tspan[1]:
                        continue
                    if any((sub.lineno, sub.col_offset)
                           <= rpos
                           <= (sub.end_lineno,
                               sub.end_col_offset)
                           for sub in trobj.finalbody):
                        continue
                    if any((sub.lineno, sub.col_offset)
                           <= ppos
                           <= (sub.end_lineno,
                               sub.end_col_offset)
                           for sub in trobj.finalbody):
                        finally_live = True
                        break
                if finally_live:
                    continue
                saved = False
                for trobj in trys:
                    if not any(
                            (sub.lineno, sub.col_offset)
                            <= rpos
                            <= (sub.end_lineno,
                                sub.end_col_offset)
                            for sub in trobj.body):
                        continue
                    if not any(catches_name_error(h.type)
                               for h in trobj.handlers):
                        continue
                    tend = (trobj.end_lineno,
                            trobj.end_col_offset)
                    if tend < ppos:
                        saved = True
                        break
                    if any((sub.lineno, sub.col_offset)
                           <= ppos
                           <= (sub.end_lineno,
                               sub.end_col_offset)
                           for sub in list(trobj.handlers)
                           + list(trobj.finalbody)):
                        saved = True
                        break
                if not saved:
                    dead = True
                    break
            _publish_dead_memo[key] = dead
            return dead

        def name_display_binds(name, capos, scope):
            # (display, bind_pos) the name may denote as
            # of capos (capture/store time): plain binds
            # at/before capos whose unwrapped value is a
            # dict/list/tuple/set display, surviving to
            # capos (a later definite bind replaces the
            # display; conditional rebinds keep both,
            # fail-closed). Aliases cost no depth;
            # rebound-away (post-capos) binds excluded.
            # For-targets excluded (they bind elements,
            # not the display). Contained names resolve
            # as-of the display's bind (binding-time
            # object provenance), not the capture.
            home = home_scope_for(name, scope, capos)
            if home is None:
                home = scope

            def _display_preserving(val, pos):
                # a rebind preserving the display's
                # observable contents: a same-object
                # alias or a shallow copy (copies share
                # descendants, which is what display
                # routing follows). Copy sources
                # resolve through capture-time identity
                # (a copy through a live alias preserves
                # too), not spelling.
                val = _unwrap_walrus(val)
                if val is None:
                    return False
                if isinstance(val, ast.Name):
                    return same_object(
                        home, val.id, name, pos, set())
                return any(same_object(home, src, name,
                                       pos, set())
                           for src in _copy_source_names(
                               val, trusted_ctor))

            def _rebind_overrides(val, pos):
                # explicit keys of a same-object unpack
                # rebind ({**src, k: v, ...} with src
                # denoting name): [(key, value)].
                # Non-override shapes yield [].
                val = _unwrap_walrus(val)
                if not isinstance(val, ast.Dict):
                    return []
                unpacked = [item for key, item in
                            zip(val.keys, val.values)
                            if key is None]
                if len(unpacked) != 1:
                    return []
                sole = unpacked[0]
                if isinstance(sole, ast.Name):
                    srcs = (sole.id,)
                else:
                    srcs = _copy_source_names(
                        sole, trusted_ctor)
                if not srcs or not any(
                        same_object(home, src, name,
                                    pos, set())
                        for src in srcs):
                    return []
                return [(key, item) for key, item in
                        zip(val.keys, val.values)
                        if key is not None]

            def _item_stores():
                # definite direct item stores to name:
                # [(pos, key, value)] for `name[key] =
                # value` reaching capos (nested stores
                # mutate descendants, never prune the
                # branch; augassign/del/for-target forms
                # stay conservative).
                out = []
                for node in ast.walk(home):
                    if isinstance(node, ast.Assign):
                        targets = node.targets
                        stored = node.value
                    elif isinstance(node, ast.AnnAssign) \
                            and node.value is not None:
                        targets = [node.target]
                        stored = node.value
                    else:
                        continue
                    for target in targets:
                        if not isinstance(
                                target, ast.Subscript) \
                                or not isinstance(
                                    target.value,
                                    ast.Name) \
                                or target.value.id != name:
                            continue
                        spos = (target.lineno,
                                target.col_offset)
                        if reaches(spos, capos):
                            out.append(
                                (spos, target.slice,
                                 stored))
                return out

            def _apply_overrides(bval, events):
                # a synthesized display with definite
                # literal overrides applied in position
                # order (dict last-wins: 0 and False are
                # one key, NaN never equals; missing keys
                # are added — routing through them must
                # see the new value). Non-literal keys
                # stay conservative (the branch may be
                # live — fail closed).
                keys = list(bval.keys)
                vals = list(bval.values)
                for okey, oval in events:
                    if not isinstance(okey, ast.Constant):
                        continue
                    hit = None
                    for idx, key in enumerate(keys):
                        if key is None or not isinstance(
                                key, ast.Constant):
                            continue
                        try:
                            matched = (key.value
                                       == okey.value)
                        except Exception:
                            matched = False
                        if matched is True:
                            hit = idx
                            break
                    if hit is None:
                        keys.append(okey)
                        vals.append(oval)
                    else:
                        vals[hit] = oval
                synth = ast.Dict(keys=keys, values=vals)
                ast.copy_location(synth, bval)
                return synth

            allbinds = scope_binds.get(
                id(home), {}).get(name, [])
            stores = _item_stores()
            displays = []
            for bpos, bkind, bval in allbinds:
                if bpos > capos or bkind != "plain":
                    continue
                bval = _unwrap_walrus(bval)
                if not isinstance(
                        bval, (ast.Dict, ast.List,
                               ast.Tuple, ast.Set)):
                    continue
                if any(bpos < later <= capos
                       and reaches(later, capos)
                       and not _display_preserving(
                           later_val, later)
                       for later, _, later_val in allbinds):
                    continue
                if isinstance(bval, ast.Dict):
                    events = []
                    for later, _, later_val in allbinds:
                        if bpos < later <= capos \
                                and reaches(later, capos):
                            for key, item in \
                                    _rebind_overrides(
                                        later_val, later):
                                events.append((later, key,
                                               item))
                    for spos, key, item in stores:
                        if bpos < spos <= capos:
                            events.append((spos, key,
                                           item))
                    events.sort(key=lambda event: event[0])
                    if events:
                        bval = _apply_overrides(
                            bval, [(key, item)
                                   for _, key, item
                                   in events])
                displays.append((bval, bpos))
            return displays

        def home_scope_for(photoname, scope, spos):
            # innermost scope from `scope` outward
            # binding photoname (globals jump to the
            # module, nonlocals and unbound names walk
            # outward, class bodies transparent to
            # deeper functions); None if unbound. A
            # class body binds a direct store only
            # through installs strictly before it —
            # before the local install executes, the
            # store sees the module binding (module
            # fallback); conditional pre-installs are
            # a documented miss (fail-open corner).
            current = scope
            while True:
                globs, nonlocs = scope_declared.get(
                    id(current), (set(), set()))
                if photoname in globs:
                    return tree
                if current is scope \
                        and isinstance(current, ast.ClassDef) \
                        and photoname not in nonlocs:
                    # LOAD_NAME applies only to names the
                    # class binds: a pre-store install
                    # reads class-local, else the module
                    # (enclosing function locals are never
                    # consulted). A name the class never
                    # mentions is a freevar/global and
                    # keeps the outward walk below (like a
                    # nonlocal name) — but an
                    # annotation-only declaration marks
                    # the name class-local without
                    # installing a value, so its loads
                    # still skip to the module. A
                    # deletion after an install unbinds
                    # it the same way; a deletion with no
                    # install before it raises, so a load
                    # after it is moot (resolved
                    # class-locally — silent when unbound,
                    # fail-closed through installs, as
                    # for any eager crash the guard does
                    # not model).
                    installs = scope_binds.get(
                        id(current), {}).get(photoname, [])

                    def class_declared():
                        # (declared-position, is_delete)
                        # pairs for the name directly in
                        # this class body (nested scopes
                        # pruned — their names are their
                        # own).
                        found = []
                        stack = list(current.body)
                        while stack:
                            node = stack.pop()
                            if isinstance(
                                    node, (ast.FunctionDef,
                                           ast.AsyncFunctionDef,
                                           ast.Lambda,
                                           ast.ClassDef)):
                                continue
                            if isinstance(
                                    node, ast.AnnAssign) \
                                    and node.value is None \
                                    and isinstance(
                                        node.target,
                                        ast.Name) \
                                    and node.target.id == \
                                    photoname:
                                found.append(
                                    ((node.lineno,
                                      node.col_offset),
                                     False))
                            elif isinstance(node, ast.Delete):
                                for target in node.targets:
                                    for leaf in \
                                            _target_leaves(
                                                target):
                                        if isinstance(
                                                leaf,
                                                ast.Name) \
                                                and leaf.id == \
                                                photoname:
                                            found.append(
                                                ((node.lineno,
                                                  node.col_offset),
                                                 True))
                                            break
                            stack.extend(
                                ast.iter_child_nodes(node))
                        return found

                    def class_trys():
                        # try statements directly in this
                        # class body (nested scopes pruned):
                        # ({id: {part: [(start, end)]}} over
                        # body/orelse/handlers/finalbody
                        # spans, {id} of trys whose body
                        # provably raises nothing — their
                        # handlers never run).
                        # Statements never straddle parts.
                        found = {}
                        quiet = set()
                        try_nodes = (ast.Try,)
                        trystar = getattr(
                            ast, "TryStar", None)
                        if trystar is not None:
                            try_nodes += (trystar,)
                        stack = list(current.body)
                        while stack:
                            node = stack.pop()
                            if isinstance(
                                    node, (ast.FunctionDef,
                                           ast.AsyncFunctionDef,
                                           ast.Lambda,
                                           ast.ClassDef)):
                                continue
                            if isinstance(node, try_nodes):
                                parts = {}
                                for part, stmts in (
                                        ("body", node.body),
                                        ("orelse",
                                         node.orelse),
                                        ("handlers",
                                         node.handlers),
                                        ("finalbody",
                                         node.finalbody)):
                                    parts[part] = [
                                        ((stmt.lineno,
                                          stmt.col_offset),
                                         (stmt.end_lineno,
                                          stmt.end_col_offset))
                                        for stmt in stmts]
                                found[id(node)] = parts
                                if _stmts_quiet(node.body):
                                    quiet.add(id(node))
                            stack.extend(
                                ast.iter_child_nodes(node))
                        return found, quiet

                    def class_withs():
                        # with statements directly in this
                        # class body (nested scopes pruned):
                        # {wid: [(start, end)]} over body
                        # spans (items evaluate before
                        # __enter__ — never suppressed).
                        found = {}
                        stack = list(current.body)
                        while stack:
                            node = stack.pop()
                            if isinstance(
                                    node, (ast.FunctionDef,
                                           ast.AsyncFunctionDef,
                                           ast.Lambda,
                                           ast.ClassDef)):
                                continue
                            if isinstance(
                                    node, (ast.With,
                                           ast.AsyncWith)):
                                found[id(node)] = [
                                    ((stmt.lineno,
                                      stmt.col_offset),
                                     (stmt.end_lineno,
                                      stmt.end_col_offset))
                                    for stmt in node.body]
                            stack.extend(
                                ast.iter_child_nodes(node))
                        return found

                    tries, quiet_trys = class_trys()
                    withs = class_withs()

                    def try_chain(pos):
                        # all (tid, part) enclosing pos,
                        # innermost first (containing
                        # spans nest; a try contributes
                        # at most one part).
                        found = []
                        for tid, parts in tries.items():
                            for part, spans in parts.items():
                                for span_start, span_end in \
                                        spans:
                                    if span_start <= pos \
                                            <= span_end:
                                        found.append(
                                            (tid, part,
                                             span_start,
                                             span_end))
                                        break
                        found.sort(key=lambda t: t[3])
                        found.sort(key=lambda t: t[2],
                                   reverse=True)
                        return [(tid, part)
                                for tid, part, _, _
                                in found]

                    def with_chain(pos):
                        # wids whose body encloses pos,
                        # innermost first.
                        found = []
                        for wid, spans in withs.items():
                            for span_start, span_end in \
                                    spans:
                                if span_start <= pos \
                                        <= span_end:
                                    found.append(
                                        (wid, span_start,
                                         span_end))
                                    break
                        found.sort(key=lambda t: t[2])
                        found.sort(key=lambda t: t[1],
                                   reverse=True)
                        return [wid for wid, _, _ in found]

                    def remainder_dead(pos, raised,
                                         raised_finally=None,
                                         suppressed=None):
                        # pos sits in a dead try-body
                        # remainder (or a skipped else):
                        # some enclosing try raised
                        # before it and pos follows the
                        # raising child. A finally nested
                        # in the remainder still runs
                        # (unwind runs finallys), as does
                        # anything before the raise — but
                        # a finally remainder past an
                        # uncaught unwind raise is dead.
                        # A with-body remainder past a
                        # suppressed raise is dead the
                        # same way (the manager swallows
                        # the raise, then control resumes
                        # past the with). A handler of a
                        # quiet try never runs (its body
                        # provably raises nothing).
                        for tid, part in try_chain(pos):
                            if part in ("body", "orelse") \
                                    and tid in raised \
                                    and pos > raised[tid]:
                                return True
                            if part == "handlers" \
                                    and tid in quiet_trys:
                                return True
                            if part == "finalbody" \
                                    and raised_finally \
                                    and tid in raised_finally \
                                    and pos > raised_finally[
                                        tid]:
                                return True
                        if suppressed:
                            for wid in with_chain(pos):
                                if wid in suppressed \
                                        and pos > suppressed[
                                            wid]:
                                    return True
                        return False

                    def try_span(tid):
                        starts = []
                        ends = []
                        for spans in tries[tid].values():
                            for start, end in spans:
                                starts.append(start)
                                ends.append(end)
                        return (min(starts), max(ends))

                    def on_stack(tid, term_pos):
                        start, end = try_span(tid)
                        return start <= term_pos <= end

                    def in_finalbody(tid, uid):
                        start, end = try_span(tid)
                        return any(
                            fstart <= start
                            and end <= fend
                            for fstart, fend in
                            tries[uid]["finalbody"])

                    def unwind_normal(chain, term_pos):
                        normal = set()
                        outer_first = list(reversed(chain))
                        for idx, (tid, _part) in enumerate(
                                outer_first):
                            for uid, _ in outer_first[:idx]:
                                if not in_finalbody(
                                        tid, uid):
                                    continue
                                if on_stack(uid, term_pos) \
                                        or uid in normal:
                                    normal.add(tid)
                                    break
                        return normal

                    def unwound_runs(pos, term_pos):
                        # pos runs during unwind past an
                        # uncaught raise at term_pos: in a
                        # finally on the unwind stack (a
                        # try enclosing the raise), or
                        # normally inside one (bodies run,
                        # handlers and elses stay
                        # conditional) — unless skipped
                        # inside its own finally by a
                        # preceding raiser.
                        if _finally_skipped(pos):
                            return False
                        chain = try_chain(pos)
                        if not chain:
                            return False
                        normal = unwind_normal(
                            chain, term_pos)
                        innermost, part = chain[0]
                        if part == "finalbody":
                            return on_stack(
                                innermost, term_pos) \
                                or innermost in normal
                        if part == "body":
                            return innermost in normal
                        return False

                    def del_runs_unwind(pos, term_pos):
                        # dels unbind liberally during
                        # unwind: provably running, or in
                        # any part of a normally-entered
                        # try (its handlers and elses may
                        # run; dead remainders were
                        # already skipped) — except in a
                        # quiet try's handler, which never
                        # runs (its body provably raises
                        # nothing to catch) — or skipped
                        # inside its own finally by a
                        # preceding raiser.
                        if _finally_skipped(pos):
                            return False
                        chain = try_chain(pos)
                        if chain \
                                and chain[0][1] == "handlers" \
                                and chain[0][0] in quiet_trys:
                            return False
                        if unwound_runs(pos, term_pos):
                            return True
                        if not chain:
                            return False
                        return chain[0][0] in unwind_normal(
                            chain, term_pos)

                    def _foreign_del_raises(stmt,
                                                delpos):
                        # a del of a name other than the
                        # queried one that may raise (no
                        # reaching bind without an
                        # intervening class-level del —
                        # an intervening del either
                        # raised already or unbound the
                        # name, so this one never runs
                        # cleanly past it either way).
                        # The queried name's own dels are
                        # replay events, never blockers.
                        if not isinstance(
                                stmt, ast.Delete):
                            return False
                        for target in stmt.targets:
                            for leaf in _target_leaves(
                                    target):
                                if not isinstance(
                                        leaf, ast.Name):
                                    continue
                                other = leaf.id
                                if other == photoname:
                                    continue
                                binds = [
                                    bpos
                                    for bpos, _, _ in
                                    scope_binds.get(
                                        id(current),
                                        {}).get(other, [])
                                    if bpos < delpos
                                    and reaches(
                                        bpos, delpos)]
                                if not binds:
                                    return True
                                stack = list(current.body)
                                while stack:
                                    node = stack.pop()
                                    if isinstance(
                                            node,
                                            (ast.FunctionDef,
                                             ast.AsyncFunctionDef,
                                             ast.Lambda,
                                             ast.ClassDef)):
                                        continue
                                    if isinstance(
                                            node,
                                            ast.Delete) \
                                            and any(
                                                bpos
                                                < (node.lineno,
                                                   node.col_offset)
                                                < delpos
                                                for bpos in
                                                binds):
                                        for cand in \
                                                node.targets:
                                            for sub in \
                                                    _target_leaves(
                                                        cand):
                                                if isinstance(
                                                        sub,
                                                        ast.Name) \
                                                        and sub.id \
                                                        == other:
                                                    return True
                                    stack.extend(
                                        ast.iter_child_nodes(
                                            node))
                        return False

                    def _finally_skipped(pos):
                        # pos skipped inside its own
                        # finally: a preceding statement
                        # in the same finally provably
                        # never falls (raise, return,
                        # constant raise — explicit
                        # control flow, independent of
                        # the queried binding's events)
                        # or a del that may raise sits
                        # before it. (A blocker inside a
                        # dead remainder over-skips —
                        # fail-closed, narrow.)
                        chain = try_chain(pos)
                        if not chain \
                                or chain[0][1] != \
                                "finalbody":
                            return False
                        tid = chain[0][0]
                        for start, end in tries[tid][
                                "finalbody"]:
                            if not start < pos:
                                continue
                            target = None
                            for node in ast.walk(current):
                                if isinstance(
                                        node, ast.stmt) \
                                        and (node.lineno,
                                             node.col_offset) \
                                        == start:
                                    target = node
                                    break
                            if target is None:
                                continue
                            if not _stmt_may_fall(
                                    target, False):
                                return True
                            if _foreign_del_raises(
                                    target, start):
                                return True
                        return False

                    def mark_unwind_raise(epos,
                                          raised_finally):
                        # an uncaught raise during unwind
                        # kills its finally remainder: a
                        # raise directly in a finally, or
                        # a raising try nested in one.
                        chain = try_chain(epos)
                        if not chain:
                            return
                        if chain[0][1] == "finalbody":
                            ftid = chain[0][0]
                            for start, end in tries[ftid][
                                    "finalbody"]:
                                if start <= epos <= end:
                                    raised_finally.setdefault(
                                        ftid, end)
                                    break
                            return
                        inner = chain[0][0]
                        _start, inner_end = try_span(inner)
                        for tid, part in chain[1:]:
                            if part != "finalbody":
                                continue
                            for start, end in tries[tid][
                                    "finalbody"]:
                                if start <= epos <= end:
                                    raised_finally.setdefault(
                                        tid, inner_end)
                                    return

                    def del_catch_info(dpos):
                        # (caught, mark, wmark) for the del
                        # at dpos, which raises NameError
                        # (nothing installed to remove).
                        # caught: an enclosing try body
                        # inside this class has a catching
                        # handler, or an enclosing with
                        # body suppresses the raise (any
                        # manager counts, as in E5 — a
                        # non-suppressing manager over-
                        # fires, fail-closed). A catcher
                        # past the class still ends the
                        # class body — only finally runs.
                        # mark: (tid, raising-child end)
                        # for class try bodies that raised
                        # on the way (their remainders
                        # past the child and elses are
                        # dead); wmark: (wid, raising-child
                        # end) for the suppressing with, or
                        # None. try orelse/finally/handler
                        # bodies do not catch their own
                        # errors.
                        target = None
                        for cand in ast.walk(current):
                            if isinstance(cand, ast.Delete) \
                                    and (cand.lineno,
                                         cand.col_offset) \
                                    == dpos:
                                target = cand
                                break
                        if target is None:
                            return True, [], None
                        try_nodes = (ast.Try,)
                        trystar = getattr(
                            ast, "TryStar", None)
                        if trystar is not None:
                            try_nodes += (trystar,)
                        mark = []
                        child = target
                        cursor = target
                        while id(cursor) in parents:
                            cursor = parents[id(cursor)]
                            if cursor is current:
                                return False, mark, None
                            if isinstance(cursor, try_nodes) \
                                    and any(sub is child
                                            for sub in
                                            cursor.body):
                                if id(cursor) in tries:
                                    mark.append(
                                        (id(cursor),
                                         (child.end_lineno,
                                          child.end_col_offset)))
                                for handler in \
                                        cursor.handlers:
                                    if catches_name_error(
                                            handler.type):
                                        return True, mark, \
                                            None
                            if isinstance(
                                    cursor,
                                    (ast.With,
                                     ast.AsyncWith)) \
                                    and any(sub is child
                                            for sub in
                                            cursor.body):
                                if id(cursor) in withs:
                                    return True, mark, (
                                        id(cursor),
                                        (child.end_lineno,
                                         child.end_col_offset))
                                return True, mark, None
                            child = cursor
                        return False, mark, None

                    declared = class_declared()
                    if installs:
                        # replay the class namespace in
                        # execution order: installs bind, a
                        # del unbinds when bound; a del with
                        # nothing to remove raises. A raise
                        # caught inside the class kills its
                        # try-body remainder and else (dead)
                        # while handlers, finally and later
                        # code continue with outer fallback;
                        # a raise escaping the class ends it
                        # (only finally-effects observe the
                        # exceptional state, and only when
                        # something outward catches — else
                        # the publish is dead too, moot).
                        # A bound store reads class-local,
                        # else the module.
                        stash = [pos
                                 for pos, _, _ in installs
                                 if pos < spos]
                        dels_before = [
                            dpos
                            for dpos, is_del in declared
                            if is_del and dpos < spos]
                        events = [(pos, False)
                                  for pos in stash]
                        events.extend(
                            (dpos, True)
                            for dpos in dels_before)
                        if not events:
                            return tree
                        bound = False
                        terminated = False
                        term_pos = None
                        raised = {}
                        raised_finally = {}
                        suppressed = {}
                        for epos, is_del in sorted(events):
                            if remainder_dead(
                                    epos, raised,
                                    raised_finally,
                                    suppressed):
                                continue
                            if terminated:
                                if not is_del:
                                    if not unwound_runs(
                                            epos, term_pos):
                                        continue
                                    bound = True
                                elif not del_runs_unwind(
                                        epos, term_pos):
                                    continue
                                elif bound:
                                    bound = False
                                else:
                                    caught2, mark2, wmark2 = \
                                        del_catch_info(epos)
                                    for tid, cend in mark2:
                                        raised.setdefault(
                                            tid, cend)
                                    if wmark2 is not None:
                                        suppressed.setdefault(
                                            wmark2[0],
                                            wmark2[1])
                                    if not caught2:
                                        mark_unwind_raise(
                                            epos,
                                            raised_finally)
                                continue
                            if not is_del:
                                if _finally_skipped(epos):
                                    continue
                                bound = True
                            elif bound:
                                bound = False
                            else:
                                caught, mark, wmark = \
                                    del_catch_info(epos)
                                for tid, cend in mark:
                                    raised.setdefault(
                                        tid, cend)
                                if wmark is not None:
                                    suppressed.setdefault(
                                        wmark[0], wmark[1])
                                # a raise inside a finally
                                # kills its remainder even
                                # when an outward catcher
                                # saves the class (control
                                # still leaves the
                                # remainder).
                                mark_unwind_raise(
                                    epos, raised_finally)
                                if not caught:
                                    terminated = True
                                    term_pos = epos
                        if terminated:
                            # only finally-effects observe
                            # the exceptional state (whether
                            # the publish past it lives is
                            # decided at the publish — a
                            # downstream publish the raise
                            # propagates past is dead).
                            if not unwound_runs(
                                    spos, term_pos):
                                return current
                            if bound:
                                return current
                            return tree
                        if remainder_dead(
                                spos, raised,
                                raised_finally,
                                suppressed):
                            return current
                        if bound:
                            return current
                        return tree
                    dels_before = [
                        dpos
                        for dpos, is_del in declared
                        if is_del and dpos < spos]
                    if dels_before:
                        terminated = False
                        term_pos = None
                        raised = {}
                        suppressed = {}
                        for dpos in sorted(dels_before):
                            if remainder_dead(
                                    dpos, raised,
                                    None, suppressed):
                                continue
                            if terminated:
                                continue
                            caught, mark, wmark = \
                                del_catch_info(dpos)
                            for tid, cend in mark:
                                raised.setdefault(tid, cend)
                            if wmark is not None:
                                suppressed.setdefault(
                                    wmark[0], wmark[1])
                            if not caught:
                                terminated = True
                                term_pos = dpos
                        if terminated:
                            if not unwound_runs(
                                    spos, term_pos):
                                return current
                            return tree
                        if remainder_dead(
                                spos, raised,
                                None, suppressed):
                            return current
                        return tree
                    if declared:
                        return tree
                binds = scope_binds.get(
                    id(current), {}).get(photoname)
                if binds is not None \
                        and photoname not in nonlocs:
                    return current
                if current is tree:
                    return None
                up = current
                while id(up) in parents:
                    up = parents[id(up)]
                    if up is tree or isinstance(
                            up, (ast.FunctionDef,
                                 ast.AsyncFunctionDef,
                                 ast.Lambda)):
                        break
                if up is current:
                    return None
                current = up

        def home_observes(home, root):
            # True when the home subtree publishes root
            # through a sink the violation side would
            # fire on (mirror of the use loop: bare
            # names in carried args, read-attr
            # receivers, results.append incl. nested
            # carriers, nested_denied carriers — with
            # the same consumer/diagnostic/sanctioned
            # exemptions). The use must resolve to the
            # home binding (lexical_binds filters
            # shadowed and outer uses; a call node sets
            # the granularity — a lambda-param shadow
            # inside one call is a documented
            # fail-closed corner). Two mirror narrows
            # (tables postdate taint): rebound-method
            # receivers are missed (exotic), and
            # clean-dict appends over-approximate
            # (fail-closed).
            want = {root}
            for node in ast.walk(home):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func
                if isinstance(called, ast.Attribute) \
                        and called.attr in read_attrs \
                        and tainted_in(called.value, want):
                    if lexical_binds(root, node) is home:
                        return True
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
                    unknown = True
                carried = [(arg.value
                            if isinstance(arg, ast.Starred)
                            else arg)
                           for arg in node.args]
                carried.extend(keyword.value
                               for keyword in node.keywords)
                if unknown:
                    if any(isinstance(arg, ast.Name)
                           and arg.id == root
                           for arg in carried) \
                            and lexical_binds(
                                root, node) is home:
                        return True
                    continue
                if opener in consumers \
                        and not rebound_consumers \
                        and opener not in builtins_attr_binds:
                    continue
                if opener in diagnostic_sinks \
                        and opener not in rebound_diagnostics \
                        and opener not in attr_binds:
                    continue
                if opener == "results.append":
                    if len(node.args) == 1 \
                            and not node.keywords:
                        only = node.args[0]
                        if isinstance(only, ast.Name) \
                                and sanctioned_at(
                                    only.id, only):
                            continue
                        if (isinstance(only, ast.Name)
                                and only.id == root
                                or tainted_in(only, want)) \
                                and lexical_binds(
                                    root, node) is home:
                            return True
                    continue
                if any(isinstance(arg, ast.Name)
                       and arg.id == root
                       for arg in carried) \
                        and lexical_binds(
                            root, node) is home:
                    return True
                if simple in nested_denied and any(
                        tainted_in(arg, want)
                        for arg in carried) \
                        and lexical_binds(
                            root, node) is home:
                    return True
            return False

        def nested_local_mates(root, scope, start, stop,
                               depth, seen, spos,
                               include_future=True):
            # a nested-local root stays local, except
            # freevar copies (resolved in their binding
            # scope — intermediate scopes included, the
            # func window only for func-bound names)
            # and copy-forms at depth >= 2 (cp =
            # outer.copy() shares descendants). Params,
            # calls and unknown values stay purely
            # local: no call graph exists (a store
            # through a nested param is a documented
            # miss). The peer's binding scope resolves
            # BEFORE any outer window is consulted: a
            # shadowing param/local never sees outside.
            # Peers resolve as-of their capturing bind
            # (later rebinds cannot touch the captured
            # object; future binds are skipped); the
            # root resolves as-of the store (forward
            # binds kept, fail-closed).
            # A bind whose name is definitively rebound
            # later in the same scope — an alias, a
            # load-free fresh value, or a bare nested
            # def — unconditionally, strictly between
            # the bind and the store, contributes nothing
            # (the store observes the new object). A
            # same-object rejoin (the killer's peer
            # already joined to the victim value) and a
            # decorated def / keyworded or based class
            # preserve instead. Binds
            # after the store, conditional rebinds and
            # unknown/copy rebinds never kill
            # (fail-closed: call timing and back-edges
            # are unknowable, copies share, unknown
            # values may flow the old object back).
            # a bare root matches a same-spelled use
            # for module homes (the module name IS the
            # same variable outward) and for
            # intermediate homes that observe it (a
            # sink in the home subtree resolving to
            # the home binding publishes the local
            # object); otherwise the bare name never
            # leaks (a nested param/local is not the
            # outer variable).
            if scope is tree or home_observes(scope, root):
                mates = {root}
            else:
                mates = set()
            if (id(scope), root, spos) in seen:
                return mates
            seen.add((id(scope), root, spos))

            def unconditional(kpos):
                # the bind at kpos executes on every
                # pass through the scope: no
                # If/Try/Match/loop/short-circuit
                # between it and the scope (scope
                # crossings transparent, as in
                # overwrites; orelse/finally arms count
                # as conditional, fail-closed).
                node = None
                for cand in ast.walk(scope):
                    if (getattr(cand, "lineno", 0),
                            getattr(cand, "col_offset",
                                    0)) == kpos:
                        node = cand
                if node is None:
                    return False
                current = node
                while current is not scope:
                    if id(current) not in parents:
                        return False
                    current = parents[id(current)]
                    if current is scope:
                        return True
                    if type(current).__name__ in (
                            "If", "Try", "TryStar",
                            "Match", "IfExp", "BoolOp",
                            "comprehension", "For",
                            "AsyncFor", "While"):
                        return False
                return True

            def kill_qualifies(victim, kpos, kkind,
                               kvalue):
                # a decorated def may hand back the old
                # object, and a class with keywords or
                # bases may inherit a metaclass (or
                # __mro_entries__) that returns it —
                # only a bare def or a baseless,
                # keywordless class binds provably fresh
                # storage.
                if kkind == "def":
                    if getattr(kvalue, "decorator_list",
                               []):
                        return False
                    if isinstance(kvalue, ast.ClassDef) \
                            and (kvalue.keywords
                                 or kvalue.bases):
                        return False
                elif kkind != "plain" \
                        or not isinstance(
                            kvalue, ast.Name) \
                        and (kvalue is None
                             or not _fresh_value(
                                 kvalue,
                                 trusted_ctor)):
                    return False
                if kkind == "plain" \
                        and isinstance(kvalue, ast.Name) \
                        and isinstance(victim, ast.Name) \
                        and same_object(
                            scope, kvalue.id, victim.id,
                            kpos, set()):
                    # a same-object rejoin preserves:
                    # the killer rebinds the name to one
                    # already joined to the victim value
                    # (self-alias, alias cycle) — the
                    # store still observes the old
                    # object.
                    return False
                return unconditional(kpos)

            def killed(pos):
                victim = None
                for _bpos, _bkind, _bval in bound_here:
                    if _bpos == pos:
                        victim = _unwrap_walrus(_bval)
                        break
                for kpos, kkind, kvalue in bound_here:
                    if not pos < kpos < spos:
                        continue
                    if kill_qualifies(victim, kpos, kkind,
                                      kvalue):
                        return True
                return False

            def outer_mates(photoname, horizon, want):
                # a peer resolves as-of the bind that
                # captured it (a later rebind of the peer
                # cannot touch the already-captured
                # object); the root resolves as-of the
                # store. Func homes keep the window
                # through the stop (the capture for
                # captured roots, unbounded above for
                # real stores). The remaining depth rides
                # along (a star hop consumes one level —
                # reusing the original depth would grant
                # a spurious extra descent).
                home = home_scope_for(
                    photoname, scope, horizon)
                if home is None or home is func:
                    return window_union(
                        photoname, start, stop)
                # module homes resolve in module binds
                # (never the func window, whose same-
                # named locals are unrelated), other
                # homes recurse lexically.
                return nested_local_mates(
                    photoname, home, start, stop,
                    want, seen, horizon,
                    include_future=False)

            bound_here = scope_binds.get(
                id(scope), {}).get(root, [])
            for _pos, kind, value in bound_here:
                if kind != "plain" or value is None:
                    continue
                if not include_future and _pos > spos:
                    # a peer resolves as-of its capture:
                    # binds after the horizon did not
                    # exist yet (the root keeps
                    # forward-ref binds, fail-closed).
                    continue
                if killed(_pos):
                    continue
                value = _unwrap_walrus(value)
                if isinstance(value, ast.Name):
                    mates.update(outer_mates(value.id, _pos, depth))
                elif depth >= 2 and isinstance(
                        value, ast.Tuple) \
                        and id(value) not in parents:
                    # a starred bind in this scope (rebinds
                    # kill it via killed() like any bind):
                    # resolve the consumed elements as the
                    # func path does, but scope-aware
                    # (func-home Names as captured at the
                    # unpack, other homes lexically
                    # as-of it; consumed copies at r>=2
                    # via their unpack-time sources).
                    def routed(photoname, level):
                        # func-home (or unbound) names
                        # resolve as captured at the unpack
                        # (post-unpack joins cannot touch
                        # the captured object); other homes
                        # resolve lexically as-of it.
                        home = home_scope_for(
                            photoname, scope, _pos)
                        if home is None or home is func:
                            return captured_union(
                                photoname, _pos, level,
                                spos)
                        return outer_mates(photoname, _pos, level)

                    _seen_nested = set()

                    def resolve_nested(consumed, level):
                        consumed = _unwrap_walrus(consumed)
                        if isinstance(consumed, ast.Name):
                            mates.update(
                                routed(consumed.id, level))
                            if (consumed.id, level) not in \
                                    _seen_nested:
                                _seen_nested.add(
                                    (consumed.id, level))
                                for disp, _ in \
                                        name_display_binds(
                                            consumed.id,
                                            horizon, scope):
                                    resolve_nested(disp,
                                                   level)
                            if level >= 2:
                                for src, _, _ in copies_at(
                                        consumed.id, _pos[0],
                                        _pos[1]):
                                    mates.update(
                                        routed(src, level))
                            return
                        if isinstance(consumed, ast.Starred):
                            resolve_nested(consumed.value,
                                           level)
                            return
                        if level < 2:
                            return
                        disp = _copy_display_operand(
                            consumed, trusted_ctor)
                        if disp is not None:
                            # a copy shares the operand
                            # display's values/elements at
                            # the same depth — resolve it
                            # structurally.
                            resolve_nested(disp, level)
                            return
                        # dicts always resolve
                        # structurally (mixed displays
                        # union unpacked and explicit
                        # values alike).
                        sources = () if isinstance(
                            consumed, ast.Dict) \
                            else _copy_source_names(
                            consumed, trusted_ctor)
                        if sources:
                            for source in sources:
                                mates.update(
                                    routed(source, level))
                                if (source, level) not in \
                                        _seen_nested:
                                    _seen_nested.add(
                                        (source, level))
                                    for disp, _ in \
                                            name_display_binds(
                                                source,
                                                horizon,
                                                scope):
                                        resolve_nested(
                                            disp, level)
                            return
                        if isinstance(consumed, (ast.List,
                                                 ast.Tuple,
                                                 ast.Set)):
                            for elt in consumed.elts:
                                if isinstance(
                                        elt, ast.Starred):
                                    resolve_nested(
                                        elt, level)
                                else:
                                    resolve_nested(
                                        elt, level - 1)
                            return
                        if isinstance(consumed, ast.Dict):
                            for key, val in zip(
                                    consumed.keys,
                                    consumed.values):
                                if key is None:
                                    resolve_nested(
                                        val, level)
                                else:
                                    resolve_nested(
                                        val, level - 1)
                            return
                    for consumed in value.elts:
                        resolve_nested(consumed, depth - 1)
                elif depth >= 2:
                    for source in _copy_source_names(
                            value, trusted_ctor):
                        mates.update(outer_mates(source, _pos, depth))
            # peers aliasing the root share its object:
            # a same-scope `peer = root` (or a chain
            # through such peers) joins while the edge
            # survives — the source unbroken between
            # the install and the store (either order;
            # a post-store install still reads the
            # stored object) and the peer unbroken
            # from the install to the store. A
            # post-store peer rebase is not tracked
            # (the sink is unknowable here — the func
            # window shares that over-approximation).
            def unbroken(name, victim, lo, hi):
                for kpos, kkind, kvalue in scope_binds.get(
                        id(scope), {}).get(name, []):
                    if not lo < kpos <= hi:
                        continue
                    if kill_qualifies(victim, kpos, kkind,
                                      kvalue):
                        return False
                return True

            peer_seen = {root}
            peer_queue = [root]
            while peer_queue:
                pname = peer_queue.pop()
                for other, pbinds in scope_binds.get(
                        id(scope), {}).items():
                    if other in peer_seen:
                        continue
                    installs = sorted(
                        (_bpos, _bval)
                        for _bpos, _bkind, _bval in pbinds
                        if _bkind == "plain")
                    for _bpos, _bval in reversed(installs):
                        _bval = _unwrap_walrus(_bval)
                        if not isinstance(_bval, ast.Name) \
                                or _bval.id != pname:
                            continue
                        lo, hi = sorted([_bpos, spos])
                        if not unbroken(pname, _bval, lo,
                                        hi):
                            continue
                        if _bpos <= spos and not unbroken(
                                other, _bval, _bpos, spos):
                            continue
                        peer_seen.add(other)
                        peer_queue.append(other)
                        break
            mates.update(peer_seen - {root})
            return mates

        def store_prefix_events(node, stmt):
            # batch events at the store's statement
            # ordered strictly before the store itself:
            # RHS effects (phase 0) always precede
            # targets (phase 1); targets compare by
            # leaf position (left-to-right).
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                probe = node
                phase = 1
                while probe is not stmt:
                    holder = parents.get(id(probe))
                    if holder is stmt \
                            and probe is stmt.value:
                        phase = 0
                    probe = holder
                    if probe is None:
                        break
                store_key = (phase, node.lineno,
                             node.col_offset)
            else:
                return []
            start = (stmt.lineno, stmt.col_offset)
            return sorted(
                (event for event in alias_events
                 if event[:2] == start
                 and event[6] < store_key),
                key=lambda event: event[2])

        def copies_for_store(root, node, depth,
                               prefix_copies):
            # {(source, copy_pos, seed)} shared-descendant
            # sources when the store lands below the
            # copy's top level (depth 1 stays local —
            # the copy owns its own keys). A
            # same-statement prefix replays its own
            # copies (later targets have not bound
            # yet); otherwise the position applies.
            if depth < 2:
                return set()
            if prefix_copies is not None:
                return set(prefix_copies)
            return set(copies_at(root, node.lineno,
                                 node.col_offset))

        def copy_source_union(source, copy_pos, stop, seed):
            # the source's groups from the copy through
            # the store window: a rebind of the source
            # to unrelated storage ends sharing (later
            # joins touch the new object) — a kill
            # after a straight-line copy, or an alias
            # to a peer outside the source's group at
            # the rebind (a same-object rejoin keeps
            # sharing). Same-statement rebinds order
            # after the copy's operand (target stores
            # run after all operands; same-batch walrus
            # rebinds stay conservative — no stop,
            # fail-closed), so a same-batch target
            # rebind stops like a later one (and the
            # sweep starts below the batch, not above
            # it). A straight-line same-batch fresh
            # target divorces an unaliased seed only
            # when nothing retains the old
            # descendants (no pre-batch copies, no
            # same-batch alias, no second same-batch
            # copy — the old object is then garbage:
            # rebound, held by no other name, later
            # copies cover their own observations,
            # window unions cover re-aliases to the
            # copy itself). A copy
            # inside a loop re-shares every iteration
            # (no kill-stop there), and an alias-stop
            # lifts when the copy and the rebind share
            # a loop with no wrap-around separator
            # (the next iteration's copy observes the
            # rebound object). Copy-rebinds never stop
            # (x.copy() shares the old descendants
            # when x is the old object).
            def wrap_open(rebind):
                # True when the innermost loop shared by
                # the copy and the rebind has no
                # wrap-around separator: no unconditional
                # kill/fresh of the source and no
                # unconditional alias move to unrelated
                # storage on the path from the rebind
                # round through the loop end back to the
                # copy (the next iteration's copy then
                # observes the rebound object, so the
                # union must keep its groups). Two runs:
                # below the loop top down to the copy
                # (every execution reaching the copy
                # passes all of it, so no straight-line
                # proof is needed — a for-target or header
                # walrus rebind counts: it re-runs every
                # pass), and the straight run after the
                # rebind's statement through transparent
                # wrappers up to the loop body end (the
                # scan stops at the first non-straight
                # statement; the orelse never counts —
                # it runs after the last copy). A
                # conditional rebind gives up fail-closed
                # (both objects may reach the next copy).
                shared = [span for span in loop_spans
                          if span[0] <= copy_pos <= span[1]
                          and span[0] <= rebind[:2]
                          <= span[1]]
                if not shared:
                    return False
                start, _end, loop = max(
                    shared, key=lambda span: span[0])
                loop_id = id(loop)
                body_start = (loop.body[0].lineno,
                              loop.body[0].col_offset)
                if not overwrites(rebind, loop_id):
                    return True

                def separates(event):
                    if event[4] != source:
                        return False
                    if start <= event[:2] < body_start \
                            and event[3] in ("kill",
                                             "alias"):
                        # a header kill/alias (a
                        # for-target or header walrus
                        # over a non-load-free value)
                        # reinstalls every pass: the next
                        # copy may observe the rebound
                        # object, so it never separates.
                        # A header FRESH (load-free
                        # value) still separates below:
                        # fresh displays yield objects no
                        # rebind can name. (Nested-loop
                        # headers in range count as before
                        # — a documented narrow.)
                        return False
                    if event[3] in ("kill", "fresh"):
                        return overwrites(event, loop_id)
                    if event[3] != "alias":
                        return False
                    grown = group_at(
                        source, event[0], event[1],
                        strict=True)
                    return event[5] not in grown \
                        and overwrites(event, loop_id)

                for event in alias_events:
                    epos = event[:2]
                    if not start <= epos < copy_pos:
                        continue
                    if separates(event):
                        return False
                rpos = rebind[:2]
                rstmt = None
                for node in ast.walk(loop):
                    if not isinstance(node, ast.stmt):
                        continue
                    spos = (node.lineno, node.col_offset)
                    if not spos <= rpos <= (
                            node.end_lineno,
                            node.end_col_offset):
                        continue
                    if rstmt is None or spos >= (
                            rstmt.lineno,
                            rstmt.col_offset):
                        rstmt = node
                if rstmt is None:
                    return True
                run_end = (rstmt.end_lineno,
                           rstmt.end_col_offset)
                node = rstmt
                while True:
                    parent = parents.get(id(node))
                    if parent is None:
                        break
                    if parent is loop:
                        seq = loop.body
                    elif isinstance(
                            parent, (ast.With,
                                     ast.AsyncWith)) \
                            and node in parent.body:
                        seq = parent.body
                    else:
                        break
                    for sib in seq[seq.index(node) + 1:]:
                        if not isinstance(
                                sib, (ast.Assign,
                                      ast.AnnAssign,
                                      ast.AugAssign,
                                      ast.Expr, ast.Pass)):
                            break
                        run_end = (sib.end_lineno,
                                   sib.end_col_offset)
                    else:
                        if parent is loop:
                            break
                        node = parent
                        continue
                    break
                for event in alias_events:
                    epos = event[:2]
                    if not rpos < epos <= run_end:
                        continue
                    if separates(event):
                        return False
                return True

            if seed == frozenset({source}) \
                    and any(event[:2] == copy_pos
                            and event[3] == "fresh"
                            and event[4] == source
                            and event[6][0] == 1
                            for event in alias_events):
                # the old object is garbage (divorced)
                # only if the batch runs whenever the
                # store does (no conditional, loop,
                # try, match or scope boundary between
                # the batch and the store window end —
                # an unbounded store never divorces),
                # and nothing retains the old
                # descendants: no pre-batch copies, no
                # same-batch alias of the source (plain
                # targets bind pre-batch RHS values, so
                # they always retain; a target walrus
                # retains only what the source denoted
                # when evaluated — a fresh rebind in an
                # earlier target leaves it holding the
                # new object), and no second same-batch
                # copy (the count includes the copy
                # itself).
                # Loop-carried self-retention (the
                # batch's own copy from an earlier pass
                # observed by a pre-batch use in the
                # same body) is a documented miss.
                batch = None
                for Archer in ast.walk(func):
                    if isinstance(Archer, ast.stmt) \
                            and (Archer.lineno,
                                 Archer.col_offset) == copy_pos:
                        batch = Archer
                        break
                if batch is None:
                    return set()
                pre = snap_at(copy_pos[0], copy_pos[1],
                              strict=True)
                if not reaches(copy_pos, stop):
                    pass
                elif pre is not None and any(
                        src == source
                        for entries in pre[1].values()
                        for src, _, _ in entries):
                    # a pre-batch copy still holds the
                    # old descendants.
                    pass
                else:
                    span_end = (batch.end_lineno,
                                batch.end_col_offset)

                    def same_batch(event):
                        # any phase, any okey shape: an
                        # event positioned inside the
                        # batch statement (target binds at
                        # its start, RHS and target
                        # walruses inside) belongs to it.
                        # (Body events of a hypothetical
                        # compound batch would over-match
                        # fail-closed; divorce batches are
                        # Assigns in practice.)
                        return copy_pos <= event[:2] <= span_end

                    def batch_trusted(name):
                        return name in ("dict", "list",
                                        "set") \
                            and name not in rebound \
                            and name not in \
                            module_attr_binds

                    def retains_old(event):
                        # a plain same-batch alias binds a
                        # pre-batch RHS value — it always
                        # retains. A walrus retainer reads
                        # the source at target-evaluation
                        # time: it retains the old object
                        # unless a fresh store to the
                        # source completes before it
                        # (completion order: the RHS,
                        # then targets left-to-right; only
                        # a provably fresh last store
                        # drops the retainer — anything
                        # else keeps it, fail-closed).
                        epos = event[:2]
                        if epos == copy_pos:
                            return True
                        walrus = None
                        for cand in ast.walk(batch):
                            if isinstance(
                                    cand,
                                    ast.NamedExpr) \
                                    and (cand.lineno,
                                         cand.col_offset) \
                                    == epos \
                                    and cand.target.id == \
                                    event[4]:
                                walrus = cand
                                break
                        if walrus is None:
                            return True
                        if batch.value is not None and any(
                                child is walrus
                                for child in ast.walk(
                                    batch.value)):
                            return True
                        targets = batch.targets \
                            if isinstance(batch,
                                         ast.Assign) \
                            else [batch.target]
                        elements = []
                        for target in targets:
                            if isinstance(
                                    target,
                                    (ast.Tuple, ast.List)):
                                elements.extend(target.elts)
                            else:
                                elements.append(target)

                        def order_key(node):
                            # completion order: a node
                            # completes when its span ends
                            # (children before parents, so a
                            # nested walrus completes before
                            # its outer one; sequential
                            # siblings keep source order).
                            for index, element in enumerate(
                                    elements):
                                if any(child is node
                                       for child in ast.walk(
                                           element)):
                                    return (index,
                                            (node.end_lineno,
                                             node.end_col_offset))
                            return None

                        wkey = order_key(walrus)
                        if wkey is None:
                            return True

                        def executes(store):
                            # a walrus store counts only when
                            # it provably runs: short-circuit
                            # right operands (BoolOp tails,
                            # IfExp arms), comprehension
                            # interiors (possibly empty) and
                            # lambda/generator bodies
                            # (deferred) may never execute.
                            probe = store
                            while probe is not batch \
                                    and id(probe) in parents:
                                child = probe
                                probe = parents[id(probe)]
                                if isinstance(
                                        probe, ast.BoolOp) \
                                        and child is not \
                                        probe.values[0]:
                                    return False
                                if isinstance(
                                        probe, ast.IfExp) \
                                        and child is not \
                                        probe.test:
                                    return False
                                if isinstance(
                                        probe,
                                        (ast.ListComp,
                                         ast.SetComp,
                                         ast.DictComp)):
                                    # result expressions may
                                    # never run (possibly
                                    # empty); generators
                                    # decide below.
                                    if child in \
                                            probe.generators:
                                        continue
                                    return False
                                if isinstance(
                                        probe,
                                        ast.comprehension):
                                    grand = parents.get(
                                        id(probe))
                                    # only the outermost
                                    # iterable runs once;
                                    # inner iterables,ifs
                                    # and results may never
                                    # run.
                                    if grand is not None \
                                            and isinstance(
                                                grand,
                                                (ast.ListComp,
                                                 ast.SetComp,
                                                 ast.DictComp)) \
                                            and grand.generators \
                                            and probe is \
                                            grand.generators[
                                                0] \
                                            and child is \
                                            probe.iter:
                                        continue
                                    return False
                                if isinstance(
                                        probe, ast.Lambda) \
                                        and child is not \
                                        probe.args:
                                    return False
                                if isinstance(
                                        probe,
                                        ast.GeneratorExp):
                                    return False
                            return True

                        if event[4] == source:
                            # a retainer that rebinds the
                            # source itself (a self-alias
                            # or a restore) holds the old
                            # object only until the next
                            # store to the source: the
                            # retained occurrence must
                            # survive the subsequent
                            # stores, so a provably fresh
                            # last subsequent store leaves
                            # it dead (it retains nothing
                            # past the batch) — anything
                            # else keeps it, fail-closed.
                            following = []
                            for target in targets:
                                for leaf, val in _walk_pairs(
                                        target, batch.value):
                                    if not isinstance(
                                            leaf, ast.Name) \
                                            or leaf.id != source:
                                        continue
                                    lkey = order_key(leaf)
                                    if lkey is None \
                                            or lkey <= wkey:
                                        continue
                                    following.append(
                                        (lkey, val))
                            for node in ast.walk(batch):
                                if not isinstance(
                                        node, ast.NamedExpr) \
                                        or node.target.id != \
                                        source:
                                    continue
                                if not executes(node):
                                    continue
                                if batch.value is not None \
                                        and any(
                                            child is node
                                            for child in ast.walk(
                                                batch.value)):
                                    # the whole RHS precedes
                                    # the targets: never
                                    # subsequent.
                                    continue
                                nkey = order_key(node)
                                if nkey is None \
                                        or nkey <= wkey:
                                    continue
                                following.append(
                                    (nkey, node.value))
                            if following \
                                    and _fresh_value(
                                        max(following,
                                            key=lambda pair:
                                                pair[0])[1],
                                        batch_trusted):
                                return False
                        # stores to the source completing
                        # before the retainer: target
                        # leaves in order, plus target
                        # walruses (their effect completes
                        # at their own position) and RHS
                        # walruses (the whole RHS precedes
                        # the targets). Only a provably
                        # fresh last store drops the
                        # retainer.
                        stores = []
                        for target in targets:
                            for leaf, val in _walk_pairs(
                                    target, batch.value):
                                if not isinstance(
                                        leaf, ast.Name) \
                                        or leaf.id != source:
                                    continue
                                lkey = order_key(leaf)
                                if lkey is None \
                                        or lkey >= wkey:
                                    continue
                                stores.append((lkey, val))
                        for node in ast.walk(batch):
                            if not isinstance(
                                    node, ast.NamedExpr) \
                                    or node.target.id != \
                                    source:
                                continue
                            if not executes(node):
                                continue
                            if batch.value is not None \
                                    and any(
                                        child is node
                                        for child in ast.walk(
                                            batch.value)):
                                nkey = (-1, (node.end_lineno,
                                             node.end_col_offset))
                            else:
                                nkey = order_key(node)
                                if nkey is None \
                                        or nkey >= wkey:
                                    continue
                            stores.append((nkey, node.value))
                        if not stores:
                            return True
                        last_val = max(
                            stores,
                            key=lambda pair: pair[0])[1]
                        return not _fresh_value(
                            last_val, batch_trusted)

                    if any(event[3] == "alias"
                           and event[5] == source
                           and same_batch(event)
                           and retains_old(event)
                           for event in alias_events):
                        pass
                    elif sum(event[3] == "copy"
                             and event[5] == source
                             and same_batch(event)
                             for event in alias_events) >= 2:
                        pass
                    else:
                        return set()
            in_loop = any(start <= copy_pos <= end
                          for start, end, _ in loop_spans)
            stop_at = None
            for event in alias_events:
                if event[:2] < copy_pos \
                        or event[4] != source:
                    continue
                if event[:2] == copy_pos \
                        and event[6][0] != 1:
                    continue
                if event[3] in ("kill", "fresh"):
                    if not in_loop:
                        stop_at = event[:2]
                        break
                elif event[3] == "alias":
                    grown = group_at(
                        source, event[0], event[1],
                        strict=True)
                    if event[5] not in grown \
                            and not wrap_open(event):
                        stop_at = event[:2]
                        break
            mates = set(seed)
            for (sline, scol), gsnap, _ in alias_snapshots:
                if (sline, scol) < copy_pos:
                    continue
                if stop is not None \
                        and (sline, scol) > stop:
                    break
                if stop_at is not None \
                        and (sline, scol) >= stop_at:
                    break
                if source in gsnap:
                    mates.update(gsnap[source])
            return mates

        def classify_sanction(name, bind):
            # sanction is EXEMPT-membership: only the
            # exact call seeds; copies share; every
            # other bind voids (fail closed).
            _pos, kind, value = bind
            if kind != "plain" or value is None:
                return (True, set(), False)
            if isinstance(value, ast.Name):
                return (False, {value.id}, False)
            if sanctioned_shape(value):
                return (False, set(), True)
            return (True, set(), False)

        # Sanctioned/fresh names: the SCC rule over
        # scope-pruned binds, resolved in the USE's
        # lexical scope (a nested bind shadows the
        # outer verdict — an outer sanction never
        # exempts a nested raw local, and a nested
        # fresh local never borrows outer trust;
        # unbound names fall outward, so a closure
        # over an unchanged outer value keeps it).
        # Order ignored (a kill anywhere voids every
        # use: loop back-edges, closures, RHS uses,
        # raw branches, repeated raw targets), seeded
        # copy cycles resolve, and lone self-copies
        # stay OUT. The lane never stores the
        # sanctioned string in a name (all relative_to
        # sites are inline), so no precision is lost
        # there.
        def scope_membership(scope, classify, memo):
            key = id(scope)
            if key not in memo:
                binds = scope_binds[key]
                outers = [
                    outer
                    for outer in lexical_use_chain(scope)
                    if not isinstance(outer, ast.ClassDef)]

                def resolve(peer):
                    for outer in outers:
                        if peer in scope_binds[id(outer)]:
                            return peer in scope_membership(
                                outer, classify, memo)
                    return False

                def resolve_same(peer):
                    if peer in binds:
                        return None
                    return resolve(peer)

                memo[key] = _scc_in(binds, classify,
                                    resolve_same)
            return memo[key]

        sanction_memo = {}
        fresh_memo = {}

        def sanctioned_at(name, node):
            scope = lexical_binds(name, node)
            if scope is None:
                return False
            return name in scope_membership(
                scope, classify_sanction, sanction_memo)

        def fresh_at(name, node):
            scope = lexical_binds(name, node)
            if scope is None:
                return False
            return name in scope_membership(
                scope, classify_fresh, fresh_memo)

        def sanction_value(value, node):
            # safe string content: a bare sanctioned
            # name, or the inline sanctioned call itself
            # (its value is a relative path string,
            # never the raw path). Recombinations
            # (out/tag) are NOT exempt — rejoining
            # rebuilds the raw path.
            if isinstance(value, ast.Name):
                return sanctioned_at(value.id, value)
            return sanctioned_shape(value)

        def fresh_value(node):
            if isinstance(node, (ast.Dict, ast.List,
                                  ast.Set)):
                return True
            if isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Name) \
                    and node.func.id in ("dict", "list",
                                         "set") \
                    and node.func.id not in rebound \
                    and node.func.id not in \
                    module_attr_binds:
                return True
            if isinstance(node, ast.Name):
                return fresh_at(node.id, node)
            if isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "copy" \
                    and not node.args and not node.keywords:
                return fresh_value(node.func.value)
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

            def taint_store(value, targets, node):
                # A tainted store into a container taints
                # the container root: the path survives
                # inside (a later append publishes it, a
                # readback resolves it). Plain names are
                # spread()'s job; namespace stores rebind
                # their key; a tainted subscript key
                # smuggles the path just like a tainted
                # value. The store lands in the group its
                # root belonged to AT the store position
                # (a later retarget never untaints an old
                # peer, and never taints a new one). A
                # sanctioned value (safe relative string)
                # does not taint: only recombinations
                # (out/tag) rebuild the raw path.
                nonlocal changed
                stored = (direct_hit(value)
                          or laundered(value)) \
                    and not sanction_value(value, node)
                for target in targets:
                    for sub in ast.walk(target):
                        if not isinstance(sub, (ast.Subscript,
                                               ast.Attribute)) \
                                or not isinstance(
                                    sub.ctx, ast.Store):
                            continue
                        hit = stored
                        if isinstance(sub, ast.Subscript):
                            hit = hit or (
                                tainted_in(sub.slice, tainted)
                                and not sanction_value(
                                    sub.slice, node))
                        if hit:
                            root, depth = _store_root(
                                sub, fresh_value)
                            if root is not None:
                                for member in group_mates(
                                        root, sub, depth):
                                    if member not in tainted:
                                        tainted.add(member)
                                        changed = True
                    for leaf in _target_leaves(target):
                        found, key = _namespace_store(leaf)
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
                # results.append itself. The receiver
                # climbs to its root (box["rows"].extend
                # taints box; a proven-fresh .copy()
                # climbs nowhere — the store lands in
                # the copy). Sanctioned values stay
                # out, like in taint_store.
                nonlocal changed
                if not isinstance(node.func, ast.Attribute) \
                        or node.func.attr not in (
                            "update", "setdefault", "extend",
                            "__setitem__"):
                    return
                receiver, depth = _store_root(
                    node.func, fresh_value)
                if receiver is None:
                    return
                carried = [arg.value
                           if isinstance(arg, ast.Starred)
                           else arg for arg in node.args]
                carried.extend(keyword.value
                               for keyword in node.keywords)
                if any((direct_hit(arg) or laundered(arg))
                       and not sanction_value(arg, node)
                       for arg in carried):
                    for member in group_mates(receiver,
                                             node, depth):
                        if member not in tainted:
                            tainted.add(member)
                            changed = True

            def taint_mutator_keys(node):
                # Namespace-mutator keys holding tainted
                # values (ns.update({"a": log})): the key
                # rebinds to the tainted value, so the
                # key name taints like a subscript-store
                # key (a sanctioned value stays out).
                nonlocal changed
                pairs = []
                is_mutator, _, _ = _namespace_mutator_keys(
                    node)
                if is_mutator:
                    args = node.args
                    if not _namespace_expr(node.func.value):
                        args = args[1:]
                    if node.func.attr in ("setdefault",
                                          "__setitem__"):
                        if len(args) >= 2 \
                                and isinstance(
                                    args[0], ast.Constant) \
                                and isinstance(
                                    args[0].value, str):
                            pairs.append((args[0].value,
                                          args[1]))
                    else:
                        for keyword in node.keywords:
                            if keyword.arg is not None:
                                pairs.append(
                                    (keyword.arg,
                                     keyword.value))
                        for arg in args:
                            if isinstance(arg, ast.Dict):
                                for key, item in zip(
                                        arg.keys, arg.values):
                                    if isinstance(
                                            key, ast.Constant) \
                                            and isinstance(
                                                key.value, str):
                                        pairs.append(
                                            (key.value, item))
                else:
                    is_ior, _, _ = _namespace_ior_keys(node)
                    if is_ior and isinstance(node.value,
                                             ast.Dict):
                        for key, item in zip(
                                node.value.keys,
                                node.value.values):
                            if isinstance(key, ast.Constant) \
                                    and isinstance(
                                        key.value, str):
                                pairs.append((key.value, item))
                for key, value in pairs:
                    if key not in tainted \
                            and (direct_hit(value)
                                 or laundered(value)) \
                            and not sanction_value(value,
                                                   node):
                        tainted.add(key)
                        changed = True

            for node in ast.walk(func):
                if isinstance(node, ast.Assign):
                    spread(node.value, list(node.targets))
                    taint_store(node.value, list(node.targets),
                                node)
                elif isinstance(node, ast.AnnAssign) \
                        and node.value is not None:
                    spread(node.value, [node.target])
                    taint_store(node.value, [node.target], node)
                elif isinstance(node, ast.AugAssign):
                    spread(node.value, [node.target])
                    taint_store(node.value, [node.target], node)
                    taint_mutator_keys(node)
                    if isinstance(node.target, ast.Name) \
                            and (direct_hit(node.value)
                                 or laundered(node.value)) \
                            and not sanction_value(
                                node.value, node):
                        # a plain-name augmented store may
                        # mutate the shared object in place:
                        # the store's groups taint with it.
                        for member in group_mates(
                                node.target.id, node, 1):
                            if member not in tainted:
                                tainted.add(member)
                                changed = True
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    spread(node.iter, [node.target])
                    taint_store(node.iter, [node.target], node)
                elif isinstance(node, ast.Call):
                    taint_receiver(node)
                    taint_mutator_keys(node)
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
        # Path.read_bytes. Name capabilities resolve
        # through the lexical scope chain at each bind
        # (caps_at); sibling scopes never leak in.
        func_rebound_methods = set()
        for node in ast.walk(func):
            if isinstance(node, (ast.For, ast.AsyncFor)):
                for leaf in _target_leaves(node.target):
                    if isinstance(leaf, ast.Attribute):
                        func_rebound_methods.add(leaf.attr)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        for leaf in _target_leaves(
                                item.optional_vars):
                            if isinstance(leaf, ast.Attribute):
                                func_rebound_methods.add(
                                    leaf.attr)
            elif isinstance(node, ast.AugAssign):
                for leaf in _target_leaves(node.target):
                    if isinstance(leaf, ast.Attribute):
                        func_rebound_methods.add(leaf.attr)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                stored = node.value
                if stored is None:
                    continue
                targets = node.targets if isinstance(
                    node, ast.Assign) else [node.target]
                for target in targets:
                    for leaf, value in _walk_pairs(target,
                                                   stored):
                        if not isinstance(leaf, ast.Attribute):
                            continue
                        if read_ref(value, caps_at(
                                node, after_value=stored)) \
                                or tainted_in(value, tainted):
                            func_rebound_methods.add(leaf.attr)
            elif isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Name) \
                    and node.func.id == "setattr" \
                    and len(node.args) >= 3 \
                    and isinstance(node.args[0], ast.Name):
                named = node.args[1]
                if isinstance(named, ast.Constant) \
                        and isinstance(named.value, str) \
                        and (read_ref(node.args[2], caps_at(
                            node, after_value=node.args[2]))
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

        def void_group(target, node):
            # a tainted store voids the groups the root
            # may land in (like taint: pre-retarget
            # stores void the old peers, post-retarget
            # stores spare them, loop back-edges
            # re-reach joined objects). The root climbs
            # through getter calls like the taint side
            # (a proven-fresh immediate copy climbs
            # nowhere — the store lands in the copy).
            root, depth = _store_root(target, fresh_value)
            if root is not None:
                for member in group_mates(root, target,
                                          depth):
                    voided.add(member)

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
                    for leaf in _target_leaves(target):
                        found, key = _namespace_store(leaf)
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
                        elif isinstance(leaf, ast.Subscript) \
                                and value is not None \
                                and ((arg_tainted(value)
                                      and not sanction_value(
                                          value, node))
                                     or (tainted_in(leaf.slice,
                                                    tainted)
                                         and not sanction_value(
                                             leaf.slice, node))):
                            void_group(leaf, node)
                        else:
                            void_names(leaf)
            elif isinstance(node, ast.AugAssign):
                found, key = _namespace_store(node.target)
                if found and key is not None:
                    voided.add(key)
                elif isinstance(node.target, ast.Subscript) \
                        and (arg_tainted(node.value)
                             or (tainted_in(node.target.slice,
                                            tainted)
                                 and not sanction_value(
                                     node.target.slice, node))):
                    void_group(node.target, node)
                elif isinstance(node.target, ast.Name):
                    # a plain-name augmented store may
                    # mutate the shared object in place:
                    # the store's groups void with it
                    # (taint spreads the same way).
                    for member in group_mates(
                            node.target.id, node, 1):
                        voided.add(member)
                else:
                    void_names(node.target)
                is_ior, ior_keys, ior_dynamic = \
                    _namespace_ior_keys(node)
                if is_ior:
                    if ior_dynamic:
                        dynamic_rebinds.append(node)
                    voided.update(ior_keys)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                for leaf in _target_leaves(node.target):
                    found, key = _namespace_store(leaf)
                    if found and key is not None:
                        voided.add(key)
                    elif isinstance(leaf, ast.Subscript) \
                            and (arg_tainted(node.iter)
                                 or (tainted_in(leaf.slice,
                                                tainted)
                                     and not sanction_value(
                                         leaf.slice, node))):
                        void_group(leaf, node)
                    else:
                        void_names(leaf)
            elif isinstance(node, ast.NamedExpr):
                void_names(node.target)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        for leaf in _target_leaves(
                                item.optional_vars):
                            found, key = _namespace_store(leaf)
                            if found and key is not None:
                                voided.add(key)
                            else:
                                void_names(leaf)
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
                    and isinstance(node.func, ast.Attribute):
                carried = [arg.value
                           if isinstance(arg, ast.Starred)
                           else arg for arg in node.args]
                carried.extend(keyword.value
                               for keyword in node.keywords)
                root, depth = _store_root(
                    node.func, fresh_value)
                if root is not None and any(
                        arg_tainted(arg)
                        and not sanction_value(arg, node)
                        for arg in carried):
                    for member in group_mates(root, node,
                                              depth):
                        voided.add(member)
                is_mutator, keys, dynamic = \
                    _namespace_mutator_keys(node)
                if is_mutator:
                    # a namespace bind through update()
                    # voids the exemption (fail-closed:
                    # no dict-display credit through a
                    # call); a computed key fails closed
                    # outright.
                    if dynamic:
                        dynamic_rebinds.append(node)
                    voided.update(keys)
        func_args = func.args
        for param in list(func_args.args) \
                + list(func_args.kwonlyargs) \
                + list(getattr(func_args, "posonlyargs", [])):
            voided.add(param.arg)
        for extra in (func_args.vararg, func_args.kwarg):
            if extra is not None:
                voided.add(extra.arg)
        # No end-state void propagation: stores void
        # the position-current group at the store
        # (plain rebinds detach, so a void through a
        # re-pointed name never touches the abandoned
        # peer — that was the X4 false positive).
        dict_bound = dict_only - voided

        def pos_clean(value):
            # Data positions recurse; a call is clean only
            # when it is the sanctioned derived-path
            # bookkeeping (str(x.relative_to(...)) — a
            # relative path string, never the raw path;
            # void when str/relative_to is rebound) or
            # holds no taint at all (a bare tainted
            # argument into any call still fires at its
            # own construction site); anything else
            # holding taint is a readable path. A bare
            # sanctioned name carries the same proven
            # string through a binding. Dict keys
            # count like values (**unpacking checks the
            # mapping itself).
            if isinstance(value, ast.Name) \
                    and sanctioned_at(value.id, value):
                return True
            if isinstance(value, ast.Call):
                if sanctioned_shape(value):
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
            for leaf in _target_leaves(target):
                found, key = _namespace_store(leaf)
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
                is_ior, ior_keys, ior_dynamic = \
                    _namespace_ior_keys(node)
                if is_ior:
                    if ior_dynamic:
                        dynamic_rebinds.append(node)
                    for key in ior_keys:
                        rebinds.setdefault(key, []).append(
                            (node.lineno, node.col_offset))
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
            elif isinstance(node, ast.Call):
                is_mutator, keys, dynamic = \
                    _namespace_mutator_keys(node)
                if is_mutator:
                    if dynamic:
                        dynamic_rebinds.append(node)
                    for key in keys:
                        rebinds.setdefault(key, []).append(
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
                    and not rebound_consumers \
                    and opener not in builtins_attr_binds:
                # Bare run_logged only: a dotted
                # .run_logged call is not the consumer
                # (an attribute-store rebind would sail
                # through an endswith exemption). A
                # builtins-rooted attribute rebind voids
                # it too (builtins.run_logged = ...);
                # any other attribute bind (Path.x =
                # ...) leaves the bare name alone.
                continue
            if opener in diagnostic_sinks \
                    and opener not in rebound_diagnostics \
                    and opener not in attr_binds:
                # an attribute bind of the sink name
                # voids it as well (builtins.print =
                # ... rebinds the bare call) — the lane
                # binds no such attributes.
                continue
            if opener == "results.append":
                if publish_dead(func, node):
                    continue
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
                            and sanctioned_at(only.id, only):
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
        # tainted argument anywhere), custom path-builder
        # wrappers outside _PATH_BUILDERS (my_join(log)
        # spreads nothing — only the listed string/path
        # combinators propagate), bindings established
        # inside comprehensions (correctly local) and
        # lambda bodies (correctly pruned — a walrus
        # there is lambda-local; only lambda defaults
        # bind outside, and lambda params shadowing a
        # capability inside the body is missed), and
        # object identity through namespace-mutator calls
        # (globals().update(a=box) neither aliases nor
        # kills), rebind-kill direction (the kill governs
        # group propagation; direct spread edges are
        # monotonic, so x = log; x = 1 still fires),
        # plain-container append
        # round-trips (x.append(log) then open(x[0]) —
        # appends don't bind; but a tainted container
        # reaching results.append fires at the append,
        # and subscript/attribute/known-mutator stores
        # propagate taint to the root), receivers
        # through computed calls (get_box().extend —
        # no resolvable owner), conditional rebinding
        # for capabilities (an if/try-guarded clean
        # rebind voids unconditionally — fail-open when
        # the branch never runs), nonlocal writes from
        # nested scopes (pruned — a nonlocal kill of an
        # outer sanction is missed), module-level
        # rebinding order against top-level calls
        # (outer scopes judge all binds at once),
        # custom .copy() methods returning owned
        # storage (only proven-fresh immediate receivers
        # are exempt), namespace identity through
        # computed wrappers (ns = get_ns()) and
        # computed module roots for __dict__
        # (sys.modules[k].__dict__ has no resolvable
        # root), sanction through AugAssign targets
        # (tag += suffix voids — fail-closed) and
        # use-before-bind (NameError at runtime),
        # setattr through a Name-held module
        # (indistinguishable from an attribute rebind),
        # new helper functions, and wholesale
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
            ("plain-call-str-spread",
             anchor,
             head + "            src = str(log.absolute())\n"
             "            output = decode_body_log("
             "open(src, \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("plain-call-join-spread",
             anchor,
             head + "            p = os.path.join(log.parent, "
             "log.name)\n"
             "            output = decode_body_log("
             "open(p, \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("sanction-rejoin-readback",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            output = decode_body_log("
             "open(out / tag, \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("nested-receiver-extend",
             anchor,
             head + "            box = {}\n"
             "            box[\"rows\"].extend([log])\n"
             "            output = decode_body_log("
             "open(box[\"rows\"], \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("container-alias-append",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            alias[\"raw\"] = log\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("container-alias-readback",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            alias[\"k\"] = log\n"
             "            output = decode_body_log("
             "open(box[\"k\"], \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("container-realias",
             anchor,
             head + "            box = {}\n"
             "            alias = {}\n"
             "            alias = box\n"
             "            alias[\"k\"] = log\n"
             "            output = decode_body_log("
             "open(box[\"k\"], \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("computed-read-ref-getattr",
             anchor,
             head + "            Path.r = getattr(Path, "
             "\"read_bytes\")\n"
             "            output = decode_body_log(log.r())\n",
             "tainted path escapes to log.r()"),
            ("computed-read-ref-dict",
             anchor,
             head + "            Path.r = "
             "Path.__dict__[\"read_bytes\"]\n"
             "            output = decode_body_log(log.r())\n",
             "tainted path escapes to log.r()"),
            ("namespace-update-sink",
             anchor,
             head + "            globals().update(_say=open)\n"
             "            with _say(log):\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to _say()"),
            ("destructured-method-rebind",
             anchor,
             head + "            Path.run_logged, unused = "
             "Path.read_bytes, None\n"
             "            output = decode_body_log("
             "log.run_logged())\n",
             "tainted path escapes to log.run_logged()"),
            ("namespace-update-dynamic",
             anchor,
             head + "            globals().update({chosen: open})\n"
             "            output = decode_body_log(captured)\n",
             "dynamic namespace rebind"),
            ("horizon-namespace-update",
             anchor,
             head + "            globals().update(captured=1)\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("horizon-namespace-setitem",
             anchor,
             head + "            globals().__setitem__("
             "\"captured\", 1)\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("horizon-namespace-setdefault",
             anchor,
             head + "            globals().setdefault(\"captured\", "
             "1)\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("sanction-str-rebind",
             anchor,
             head + "            globals()[\"str\"] = "
             "Path.read_bytes\n"
             "            results.append({\"data\": "
             "str(log.relative_to(out))})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-relative-to-rebind",
             anchor,
             head + "            Path.relative_to = "
             "lambda self, other: self\n"
             "            results.append({\"p\": "
             "str(log.relative_to(out))})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-tainted-callee",
             anchor,
             head + "            str = log.rename\n"
             "            results.append({\"p\": "
             "str(out.relative_to(root))})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-retro-publish",
             anchor,
             head + "            tag = log\n"
             "            results.append({\"raw\": tag})\n"
             "            tag = str(log.relative_to(out))\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-swap-laundering",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            alt = log\n"
             "            tag, alt = alt, tag\n"
             "            results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("destructured-starred-rebind",
             anchor,
             head + "            Path.r, *unused = "
             "(Path.read_bytes, None, None)\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("destructured-conditional-rhs",
             anchor,
             head + "            Path.r, unused = "
             "(Path.read_bytes if flag else None), None\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("for-attribute-rebind",
             anchor,
             head + "            for Path.relative_to in "
             "[lambda self, other: self]:\n"
             "                results.append({\"raw\": "
             "str(log.relative_to(out))})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("with-attribute-rebind",
             anchor,
             head + "            with open(\"x\") as Path.r:\n"
             "                pass\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("augassign-alias-store",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            alias |= {\"raw\": log}\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("call-receiver-mutation",
             anchor,
             head + "            box = {\"rows\": []}\n"
             "            box.get(\"rows\").extend([log])\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("readcap-plain-name",
             anchor,
             head + "            rb = Path.read_bytes\n"
             "            Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("readcap-chain",
             anchor,
             head + "            rb = Path.read_bytes\n"
             "            rb2 = rb\n"
             "            Path.r = rb2\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("namespace-unbound-update",
             anchor,
             head + "            dict.update(globals(), "
             "_say=Path.read_bytes)\n"
             "            with _say(log):\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to _say()"),
            ("namespace-alias-store",
             anchor,
             head + "            ns = globals()\n"
             "            ns[\"_say\"] = open\n"
             "            with _say(log):\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to _say()"),
            ("namespace-arg-dynamic",
             anchor,
             head + "            evil(globals())\n"
             "            output = decode_body_log(captured)\n",
             "dynamic namespace rebind"),
            ("sanction-method-def-rebind",
             anchor,
             head + "            class _Rel(str):\n"
             "                def relative_to(self, _o): "
             "return self\n"
             "            tag = str(_Rel(f\"{log}\")"
             ".relative_to(out))\n"
             "            results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("plain-call-expanduser-spread",
             anchor,
             head + "            p = os.path.expanduser(f\"{log}\")\n"
             "            output = decode_body_log("
             "open(p, \"rb\").read())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to open()"),
            ("nested-posixpath-construction",
             anchor,
             head + "            p = PosixPath(str(log.parent))\n"
             "            output = decode_body_log("
             "open(p, \"rb\").read())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to PosixPath()"),
            ("sanction-reseed-publish",
             anchor,
             head + "            tag = log\n"
             "            tag = str(log.relative_to(out))\n"
             "            results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-loop-backedge-kill",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            for _i in range(2):\n"
             "                results.append({\"p\": tag})\n"
             "                tag = log\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-closure-kill",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            publish = lambda: "
             "results.append({\"p\": tag})\n"
             "            tag = log\n"
             "            publish()\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-rhs-use",
             anchor,
             head + "            tag = log\n"
             "            tag, _ = str(log.relative_to(out)), "
             "results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-branch-raw",
             anchor,
             head + "            if code:\n"
             "                tag = log\n"
             "            else:\n"
             "                tag = str(log.relative_to(out))\n"
             "            results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-walrus-rhs-use",
             anchor,
             head + "            tag = f\"{log}\"\n"
             "            if (tag := str(log.relative_to("
             "(results.append({\"raw\": tag}), out)[1]))):\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-repeated-targets",
             anchor,
             head + "            tag, tag = "
             "str(log.relative_to(out)), f\"{log}\"\n"
             "            results.append({\"raw\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-preretarget-store",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            fresh = {}\n"
             "            alias[\"raw\"] = str(log)\n"
             "            alias = fresh\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-self-assign",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            a = a\n"
             "            a[\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-tuple-swap",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            fresh = {}\n"
             "            a, fresh = fresh, a\n"
             "            fresh[\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-augassign-attr-ror",
             anchor,
             head + "            class _Spoof:\n"
             "                def __ror__(self, _other):\n"
             "                    return lambda path, _base: path\n"
             "            Path.relative_to |= _Spoof()\n"
             "            results.append({\"p\": "
             "str(log.relative_to(out))})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-augassign-attr-radd",
             anchor,
             head + "            class Replace:\n"
             "                def __radd__(self, previous):\n"
             "                    return lambda path, base: path\n"
             "            Path.relative_to += Replace()\n"
             "            results.append({\"raw\": "
             "str(log.relative_to(out))})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("readcap-augassign-attr",
             anchor,
             head + "            class _Spoof2:\n"
             "                def __ror__(self, _other):\n"
             "                    return Path.read_bytes\n"
             "            Path.r |= _Spoof2()\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("namespace-ior-update",
             anchor,
             head + "            ns = globals()\n"
             "            ns |= {\"_say\": open}\n"
             "            with _say(log):\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to _say()"),
            ("namespace-dunder-ior",
             anchor,
             head + "            globals().__ior__({\"_say\": open})\n"
             "            with _say(log):\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to _say()"),
            ("namespace-update-alias-dynamic",
             anchor,
             head + "            upd = globals().update\n"
             "            upd(_say=open)\n"
             "            output = decode_body_log(captured)\n",
             "dynamic namespace rebind"),
            ("namespace-bare-globals",
             anchor,
             head + "            g = globals\n"
             "            g()[\"_say\"] = open\n"
             "            with _say(log):\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to _say()"),
            ("namespace-evil-update-dynamic",
             anchor,
             head + "            class Evil:\n"
             "                def update(self, namespace, **kwargs):\n"
             "                    namespace[\"_say\"] = Path.read_bytes\n"
             "            evil = Evil()\n"
             "            evil.update(globals(), clean=1)\n"
             "            _say(log)\n"
             "            output = decode_body_log(captured)\n",
             "dynamic namespace rebind"),
            ("sanction-builtins-str",
             anchor,
             head + "            import builtins\n"
             "            builtins.str = lambda p: p\n"
             "            results.append({\"p\": "
             "str(log.relative_to(out))})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sink-builtins-print",
             anchor,
             head + "            import builtins\n"
             "            builtins.print = lambda p: p\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
            ("consumer-builtins-run-logged",
             anchor,
             head + "            import builtins\n"
             "            builtins.run_logged = "
             "lambda *a: (0, False, b\"\")\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to run_logged()"),
            ("namespace-update-dictarg-taint",
             anchor,
             head + "            ns = globals()\n"
             "            ns.update({\"a\": log})\n"
             "            open(a)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to open()"),
            ("readcap-install-then-clean",
             anchor,
             head + "            rb = Path.read_bytes\n"
             "            Path.r = rb\n"
             "            rb = None\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("readcap-for-install",
             anchor,
             head + "            for rb in (Path.read_bytes,):\n"
             "                Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("readcap-param-install",
             anchor,
             head + "            def inst(rb=Path.read_bytes):\n"
             "                Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("readcap-lambda-walrus-kept",
             anchor,
             head + "            rb = Path.read_bytes\n"
             "            f = lambda: (rb := None)\n"
             "            Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("readcap-copy-before-kill",
             anchor,
             head + "            rb = Path.read_bytes\n"
             "            rb2 = rb\n"
             "            rb = None\n"
             "            Path.r = rb2\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("readcap-cycle-seeded",
             anchor,
             head + "            rb = Path.read_bytes\n"
             "            rb2 = rb\n"
             "            rb = rb2\n"
             "            Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("alias-loop-store",
             anchor,
             head + "            box = {}\n"
             "            alias = {}\n"
             "            for _ in range(2):\n"
             "                alias[\"raw\"] = f\"{log}\"\n"
             "                alias = box\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-closure-store",
             anchor,
             head + "            box = {}\n"
             "            alias = {}\n"
             "            def stash():\n"
             "                alias[\"raw\"] = f\"{log}\"\n"
             "            alias = box\n"
             "            stash()\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("shallow-copy-nested-update",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            box.copy()[\"rows\"].update("
             "{\"raw\": log})\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("shallow-copy-nested-store",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            box.copy()[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-selfcopy-only",
             anchor,
             head + "            globals().update(tag=f\"{log}\")\n"
             "            class K:\n"
             "                tag = tag\n"
             "            results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("sanction-class-seed-flat",
             anchor,
             head + "            globals().update(tag=f\"{log}\")\n"
             "            class K:\n"
             "                tag = str(log.relative_to(out))\n"
             "            results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("consumer-computed-root",
             anchor,
             head + "            import sys\n"
             "            sys.modules[__name__].run_logged = "
             "lambda *a, **k: (0, False, b\"\")\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to run_logged()"),
            ("sink-builtins-dict",
             anchor,
             head + "            import builtins\n"
             "            builtins.__dict__[\"print\"] = "
             "Path.read_bytes\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
            ("sink-dunder-builtins",
             anchor,
             head + "            __builtins__[\"print\"] = "
             "Path.read_bytes\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
            ("alias-samestatement-store",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            alias[\"raw\"] = alias = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-rhs-tuple-order",
             anchor,
             head + "            box = {}\n"
             "            fresh = {}\n"
             "            a = box\n"
             "            a[\"raw\"], a = log, fresh\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-rhs-call-mutates",
             anchor,
             head + "            box = {}\n"
             "            fresh = {}\n"
             "            a = box\n"
             "            a = (a.update({\"raw\": log}), fresh)[1]\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-ungrouped-batch",
             anchor,
             head + "            box = {}\n"
             "            a, b, box = box, box, {}\n"
             "            a[\"raw\"] = log\n"
             "            results.append(b)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-repeat-order",
             anchor,
             head + "            z = {}\n"
             "            y = {}\n"
             "            a, a = z, y\n"
             "            a[\"raw\"] = log\n"
             "            results.append(y)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("alias-repeat-snapshot",
             anchor,
             head + "            box = {}\n"
             "            z = {}\n"
             "            a = box\n"
             "            a, a = z, a\n"
             "            a[\"raw\"] = log\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("namespace-ior-horizon",
             anchor,
             head + "            ns = globals()\n"
             "            ns |= {\"captured\": b\"replacement\"}\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused"),
            ("namespace-shadowed-dict",
             anchor,
             head + "            class dict:\n"
             "                @staticmethod\n"
             "                def update(ns, **kwargs):\n"
             "                    ns[\"_say\"] = open\n"
             "            dict.update(globals(), clean=1)\n"
             "            _say(log)\n"
             "            output = decode_body_log(captured)\n",
             "dynamic namespace rebind"),
            ("c1-batch-peer-store",
             anchor,
             head + "            alias = {}\n"
             "            a = alias\n"
             "            a[\"raw\"] = log\n"
             "            results.append(alias)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("c2-rebind-before-store",
             anchor,
             head + "            box = {}\n"
             "            a = {}\n"
             "            a, a[\"raw\"] = box, log\n"
             "            a = {}\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("c3-nested-sanction-shadow",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            def inner():\n"
             "                tag = log\n"
             "                results.append({\"p\": tag})\n"
             "            inner()\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("c3b-class-sanction-shadow",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            class K:\n"
             "                tag = log\n"
             "                results.append({\"p\": tag})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("c10-clean-before-seed",
             anchor,
             head + "            rb = None\n"
             "            rb = Path.read_bytes\n"
             "            Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("c10b-loop-seed-after-clean",
             anchor,
             head + "            rb = None\n"
             "            for _ in range(2):\n"
             "                rb = Path.read_bytes\n"
             "            Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("c11-outer-clean-after-install",
             anchor,
             head + "            rb = Path.read_bytes\n"
             "            def install():\n"
             "                Path.r = rb\n"
             "            install()\n"
             "            rb = None\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("c12-rhs-walrus-order",
             anchor,
             head + "            box = {}\n"
             "            a = {}\n"
             "            a, b = (a := box), a\n"
             "            b[\"raw\"] = log\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("c13-stored-shallow-copy",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = box.copy()\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("c14-builtins-ior",
             anchor,
             head + "            global __builtins__\n"
             "            __builtins__ |= {\"print\": open}\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
            ("f3-class-cap-install",
             anchor,
             head + "            class K:\n"
             "                rb = Path.read_bytes\n"
             "                Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("f3b-lambda-default-setattr",
             anchor,
             head + "            f = lambda rb=Path.read_bytes: "
             "setattr(Path, \"r\", rb)\n"
             "            f()\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("f4-composed-backedge",
             anchor,
             head + "            b = {}\n"
             "            safe = {}\n"
             "            for _i in range(2):\n"
             "                a = b\n"
             "                a[\"raw\"] = log\n"
             "                b = safe\n"
             "            results.append(safe)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("f5-comprehension-backedge",
             anchor,
             head + "            box = {}\n"
             "            safe = {}\n"
             "            _tmp = [(box.update({\"raw\": log}), "
             "box := safe)[0] for _ in range(2)]\n"
             "            results.append(safe)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("f6-def-in-loop-call",
             anchor,
             head + "            safe = {}\n"
             "            other = {}\n"
             "            for _i in range(2):\n"
             "                box = safe\n"
             "                if _i: f()\n"
             "                box = other\n"
             "                def f(): box.update({\"raw\": log})\n"
             "            results.append(safe)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("f7b-dict-copy-descendant",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = dict(box)\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("f7c-spread-copy-descendant",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = {**box}\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("f8a-builtins-alias-dict",
             anchor,
             head + "            import builtins as b\n"
             "            b.__dict__[\"print\"] = Path.read_bytes\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
            ("s1-default-sanction-scope",
             anchor,
             head + "            tag = log\n"
             "            def f(x=results.append({\"p\": tag})):\n"
             "                tag = str(log.relative_to(out))\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("s1b-builtins-default-shadow",
             anchor,
             head + "            import builtins as b\n"
             "            def f(b=0, x=b.__dict__.__setitem__"
             "(\"print\", Path.read_bytes)):\n"
             "                pass\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
            ("s2-phase-split-walrus",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            other = {}\n"
             "            b, c = a, (a := other)\n"
             "            b[\"raw\"] = log\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("s3-bfs-last-bind",
             anchor,
             head + "            rb = None\n"
             "            if True:\n"
             "                rb = None\n"
             "            rb = Path.read_bytes\n"
             "            Path.r = rb\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("s4-cap-query-rhs-order",
             anchor,
             head + "            def install():\n"
             "                rb = None\n"
             "                dummy, Path.r = "
             "(rb := Path.read_bytes), rb\n"
             "            install()\n"
             "            output = decode_body_log(log.r())\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.r()"),
            ("s6-freevar-chain",
             anchor,
             head + "            box = {}\n"
             "            def outer():\n"
             "                a = box\n"
             "                def inner():\n"
             "                    b = a\n"
             "                    b[\"raw\"] = log\n"
             "                inner()\n"
             "            outer()\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("s9-composed-copy",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = box.copy().copy()\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("s9b-dict-of-copy",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = dict(box.copy())\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("s9c-spread-of-spread",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = {**{**box}}\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("s10-walrus-receiver",
             anchor,
             head + "            box = {}\n"
             "            a = {}\n"
             "            (a := box)[\"raw\"] = log\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("s11-builtins-ior-bypass",
             anchor,
             head + "            import builtins as b\n"
             "            try:\n"
             "                b.__dict__ |= "
             "{\"print\": Path.read_bytes}\n"
             "            except AttributeError:\n"
             "                pass\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
            ("s11b-direct-module-attr",
             anchor,
             head + "            import builtins\n"
             "            try:\n"
             "                builtins.__dict__ |= "
             "{\"print\": Path.read_bytes}\n"
             "            except AttributeError:\n"
             "                pass\n"
             "            print(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to print()"),
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
            ("sanction-bound-publish",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            results.append({\"p\": tag})\n" + use),
            ("sanction-bound-store",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            box = {}\n"
             "            box[\"k\"] = tag\n"
             "            results.append(box)\n" + use),
            ("alias-clean-bookkeeping",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            alias[\"k\"] = 1\n"
             "            results.append(box)\n" + use),
            ("alias-rebind-kill",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            alias = {}\n"
             "            alias[\"k\"] = log\n"
             "            output = decode_body_log("
             "open(box[\"k\"], \"rb\").read())\n" + use),
            ("computed-read-ref-constant",
             anchor,
             head + "            Path.label = \"x\"\n"
             "            output = decode_body_log(log.label())\n"
             + use),
            ("namespace-update-clean",
             anchor,
             head + "            globals().update(clean=1)\n" + use),
            ("sanction-genuine-clean",
             anchor,
             head + "            results.append({\"p\": "
             "str(out.relative_to(root))})\n" + use),
            ("alias-retarget-clean",
             anchor,
             head + "            box = {}\n"
             "            alias = box\n"
             "            fresh = {}\n"
             "            alias = fresh\n"
             "            alias[\"raw\"] = log\n"
             "            results.append(box)\n" + use),
            ("sanctioned-slice-store",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            box = {}\n"
             "            box[tag] = 1\n"
             "            results.append(box)\n" + use),
            ("sanction-walrus-seed",
             anchor,
             head + "            if (tag := "
             "str(log.relative_to(out))):\n"
             "                results.append({\"p\": tag})\n" + use),
            ("readcap-clean-rebind",
             anchor,
             head + "            def clean(self):\n"
             "                return \"harmless\"\n"
             "            rb = Path.read_bytes\n"
             "            rb = clean\n"
             "            Path.r = rb\n"
             "            log.r()\n" + use),
            ("fresh-copy-update",
             anchor,
             head + "            box = {}\n"
             "            box.copy().update({\"raw\": log})\n"
             "            results.append(box)\n" + use),
            ("sanction-cycle-seeded-silent",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            tag2 = tag\n"
             "            tag = tag2\n"
             "            results.append({\"p\": tag})\n" + use),
            ("readcap-unseeded-cycle-silent",
             anchor,
             head + "            rb2 = rb\n"
             "            rb = rb2\n"
             "            Path.r = rb\n"
             "            log.r()\n" + use),
            ("alias-repeat-abandoned-silent",
             anchor,
             head + "            z = {}\n"
             "            y = {}\n"
             "            a, a = z, y\n"
             "            a[\"raw\"] = log\n"
             "            results.append(z)\n" + use),
            ("c6-repeat-detached-peer-silent",
             anchor,
             head + "            box = {}\n"
             "            a, a, box = box, box, {}\n"
             "            a[\"raw\"] = log\n"
             "            results.append(box)\n" + use),
            ("c7-nested-local-store-silent",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            def stash():\n"
             "                a = {}\n"
             "                a[\"raw\"] = log\n"
             "            stash()\n"
             "            results.append(box)\n" + use),
            ("c7b-nested-walrus-store-silent",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            def stash():\n"
             "                (a := {})[\"raw\"] = log\n"
             "            stash()\n"
             "            results.append(box)\n" + use),
            ("c8-immediate-copy-subscript-silent",
             anchor,
             head + "            box = {}\n"
             "            box.copy()[\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n" + use),
            ("c8b-update-spelling-silent",
             anchor,
             head + "            box = {}\n"
             "            box.copy().update({\"raw\": log})\n"
             "            results.append(box)\n" + use),
            ("c9-ctor-copy-silent",
             anchor,
             head + "            box = dict()\n"
             "            box.copy().update({\"raw\": log})\n"
             "            results.append(box)\n" + use),
            ("c9b-list-ctor-silent",
             anchor,
             head + "            box = list()\n"
             "            box.copy().update({\"raw\": log})\n"
             "            results.append(box)\n" + use),
            ("c13-copy-top-write-silent",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = box.copy()\n"
             "            cp[\"raw\"] = f\"{log}\"\n"
             "            results.append(box)\n" + use),
            ("s1c-clean-default-shadow-silent",
             anchor,
             head + "            tag = str(log.relative_to(out))\n"
             "            def f(x=results.append({\"p\": tag})):\n"
             "                tag = log\n" + use),
            ("s2b-converse-clean-silent",
             anchor,
             head + "            box = {}\n"
             "            a = {}\n"
             "            b, c = a, (a := box)\n"
             "            b[\"raw\"] = log\n"
             "            results.append(a)\n" + use),
            ("s5-nested-param-copy-silent",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            def f(a):\n"
             "                b = a\n"
             "                b[\"raw\"] = log\n"
             "            f({})\n"
             "            results.append(box)\n" + use),
            ("s5b-nested-local-init-silent",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            def f():\n"
             "                a = {}\n"
             "                b = a\n"
             "                b[\"raw\"] = log\n"
             "            f()\n"
             "            results.append(box)\n" + use),
            ("s7-copy-provenance-rebind-silent",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = box.copy()\n"
             "            other = {\"rows\": {}}\n"
             "            box = other\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(other)\n" + use),
            ("s7b-rebind-control-silent",
             anchor,
             head + "            box = {\"rows\": {}}\n"
             "            cp = box.copy()\n"
             "            other = {\"rows\": {}}\n"
             "            box = {}\n"
             "            box = other\n"
             "            cp[\"rows\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(other)\n" + use),
            ("t1s-loop-separator-silent",
             anchor,
             head + "            box = {\"row\": {}}\n"
             "            other = {\"row\": {}}\n"
             "            for i in range(2):\n"
             "                cp = box.copy()\n"
             "                box = other\n"
             "                box = {}\n"
             "                cp[\"row\"][\"raw\"] = f\"{log}\"\n"
             "            results.append(other)\n" + use),
            ("t5b-reversed-completion-silent",
             anchor,
             head + "            def clean(self):\n"
             "                return None\n"
             "            rb, dummy = clean, (rb := Path.read_bytes)\n"
             "            Path.r = rb\n"
             "            ignored = decode_body_log(log.r())\n" + use),
            ("t7b-intermediate-shadow-silent",
             anchor,
             head + "            box = {}\n"
             "            a = box\n"
             "            def outer():\n"
             "                a = {}\n"
             "                def inner():\n"
             "                    a[\"raw\"] = log\n"
             "                inner()\n"
             "            outer()\n"
             "            results.append(box)\n" + use),
            ("t8b-class-clean-silent",
             anchor,
             head + "            box = {}\n"
             "            class C:\n"
             "                a = {}\n"
             "                b = a\n"
             "                b[\"raw\"] = log\n"
             "            results.append(box)\n" + use),
            ("t9-starred-target-silent",
             anchor,
             head + "            box = {}\n"
             "            other = {}\n"
             "            *a, b = box, other\n"
             "            a[0] = log\n"
             "            results.append(box)\n" + use),
            ("w5b-reversed-target-walrus-silent",
             anchor,
             head + "            def clean(self):\n"
             "                return None\n"
             "            rb = Path.read_bytes\n"
             "            container = {}\n"
             "            rb, container[(rb := clean)] = "
             "Path.read_bytes, None\n"
             "            Path.r = rb\n"
             "            ignored = decode_body_log(log.r())\n"
             + use),
            ("w6c-alias-replay-silent",
             anchor,
             head + "            box = {}\n"
             "            a = {}\n"
             "            dummy = (z := ((a := box), {})[1])\n"
             "            z[\"raw\"] = log\n"
             "            results.append(box)\n" + use),
        ]
        for name, find, repl in cases:
            with self.subTest(shape=name):
                self.assertEqual(source.count(find), 1, name)
                self.assertEqual(
                    _binding_violations(source.replace(find, repl)),
                    [], name)

    def test_tripwire_catches_r25_module_level_plants(self):
        # adjudication-r25 plants that need a module-top
        # edit (a single anchor swap cannot express
        # them): module-held capability (C4), top-level
        # def shadowing a diagnostic sink (F8b/F8b2 with
        # its bare-print control), the documented
        # loop-union over-taint pin (M-P), and the
        # annotation walrus (C5 — a real 3.12 runtime
        # rebind; 3.14 rejects it only at compile time,
        # after ast.parse, so the guard still fires on
        # both and no version gate is needed).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ("c4-module-cap-closure",
             [(mod, "rb = Path.read_bytes\n" + mod),
              (anchor,
               head + "            rb2 = rb\n"
               "            def install():\n"
               "                Path.r = rb2\n"
               "            install()\n"
               "            output = decode_body_log(log.r())\n"
               + use)],
             "tainted path escapes to log.r()"),
            ("c5-annotation-walrus",
             [(anchor,
               head + "            tag = str(log.relative_to(out))\n"
               "            def f(x: (tag := log)):\n"
               "                pass\n"
               "            results.append({\"p\": tag})\n"
               + use)],
             "tainted path escapes to results.append()"),
            ("f8b-def-print-shadow",
             [(mod,
               "def print(p):\n"
               "    return __import__(\"pathlib\").Path(p)"
               ".read_bytes()\n" + mod),
              (anchor, head + "            print(log)\n" + use)],
             "tainted path escapes to print()"),
            ("f8b2-exfil-shadow",
             [(mod,
               "def print(p):\n"
               "    results.append(p)\n" + mod),
              (anchor, head + "            print(log)\n" + use)],
             "tainted path escapes to print()"),
            ("m-p-loop-overtaint",
             [(anchor,
               head + "            box = {}\n"
               "            for _ in range(2):\n"
               "                a = {}\n"
               "                a[\"raw\"] = log\n"
               "                a = box\n"
               "            results.append(box)\n"
               + use)],
             "tainted path escapes to results.append()"),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")
        with self.subTest(shape="f8b-control-bare-print"):
            planted = source.replace(
                anchor, head + "            print(log)\n" + use)
            self.assertEqual(_binding_violations(planted), [])

    def test_tripwire_catches_r27_prelude_plants(self):
        # adjudication-r26 S8: the conditional loop-alias
        # join must fire at every placement — the anchor
        # plant sits inside an enclosing loop whose
        # context accidentally masks the omitted right
        # endpoint, so the single-loop miss needs the
        # function-top (prelude) site too. Nested-loop
        # variants fire at both sites.
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        single = ("    box = {}\n"
                  "    a = {}\n"
                  "    for i in range(3):\n"
                  "        if i == 2: a = box\n"
                  "        if i == 0: a = {}\n"
                  "        a[\"raw\"] = log\n"
                  "    results.append(box)\n")
        nested = ("    box = {}\n"
                  "    a = {}\n"
                  "    for _ in range(2):\n"
                  "        for i in range(3):\n"
                  "            if i == 2: a = box\n"
                  "            if i == 0: a = {}\n"
                  "            a[\"raw\"] = log\n"
                  "    results.append(box)\n")
        indented = "\n".join(
            "        " + line if line.strip() else line
            for line in single.splitlines()) + "\n"
        cases = [
            ("s8-prelude-single",
             [(prelude, prelude + single)]),
            ("s8-prelude-nested",
             [(prelude, prelude + nested)]),
            ("s8-anchor-single",
             [(anchor, head + indented + use)]),
        ]
        fragment = "tainted path escapes to results.append()"
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_catches_r28_plants(self):
        # adjudication-r27 T-fixes, anchor placement
        # (t6b needs its module-top alias): loop copy
        # re-sharing across a rebind (T1), self-walrus
        # and self-copy source capture (T4/T4b),
        # completion-ordered binds (T5), module-home
        # alias precision (T6b), intermediate-scope
        # freevar stores (T7), class-body stores (T8),
        # static RHS stars (T9b).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        sunk = "tainted path escapes to results.append()"
        fire = [
            ("t1-loop-reshare",
             [(anchor,
               head + "            box = {\"row\": {}}\n"
               "            other = {\"row\": {}}\n"
               "            for i in range(2):\n"
               "                cp = box.copy()\n"
               "                box = other\n"
               "                cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "            results.append(other)\n"
               + use)],
             sunk),
            ("t4-self-walrus",
             [(anchor,
               head + "            box = {}\n"
               "            a = box\n"
               "            dummy = (a := a)\n"
               "            a[\"raw\"] = log\n"
               "            results.append(box)\n"
               + use)],
             sunk),
            ("t4b-self-copy",
             [(anchor,
               head + "            box = {\"row\": {}}\n"
               "            cp = box.copy()\n"
               "            dummy = (cp := cp.copy())\n"
               "            cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "            results.append(box)\n"
               + use)],
             sunk),
            ("t5-bind-completion",
             [(anchor,
               head + "            def clean(self):\n"
               "                return None\n"
               "            rb, dummy = Path.read_bytes, (rb := clean)\n"
               "            Path.r = rb\n"
               "            ignored = decode_body_log(log.r())\n"
               + use)],
             "tainted path escapes to log.r()"),
            ("t6b-module-alias",
             [(mod, "m_t6b = {}\na_t6b = m_t6b\n" + mod),
              (anchor,
               head + "            def f():\n"
               "                global a_t6b\n"
               "                b = a_t6b\n"
               "                b[\"raw\"] = log\n"
               "            f()\n"
               "            results.append(m_t6b)\n"
               + use)],
             sunk),
            ("t7-direct-freevar-store",
             [(anchor,
               head + "            box = {}\n"
               "            def outer():\n"
               "                a = box\n"
               "                def inner():\n"
               "                    a[\"raw\"] = log\n"
               "                inner()\n"
               "            outer()\n"
               "            results.append(box)\n"
               + use)],
             sunk),
            ("t8-class-body-store",
             [(anchor,
               head + "            box = {}\n"
               "            class C:\n"
               "                a = box\n"
               "                b = a\n"
               "                b[\"raw\"] = log\n"
               "            results.append(box)\n"
               + use)],
             sunk),
            ("t9b-rhs-star-miss",
             [(anchor,
               head + "            box = {}\n"
               "            a, b = *[box], {}\n"
               "            a[\"raw\"] = log\n"
               "            results.append(box)\n"
               + use)],
             sunk),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_catches_r28_prelude_plants(self):
        # adjudication-r27 prelude placements: the
        # anchor sits inside a lane loop whose context
        # masks the T2 endpoint shape both sides and
        # the T3 copy-after-walrus on the base side, so
        # the loop reshare (T1p) and the copy after a
        # walrus re-point (T3p) pin the function-top
        # site, where the prelude T2 silence pins the
        # endpoint-identity fix (next test).
        source = Path(lane.__file__).read_text()
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        t1p = ("    box = {\"row\": {}}\n"
               "    other = {\"row\": {}}\n"
               "    for i in range(2):\n"
               "        cp = box.copy()\n"
               "        box = other\n"
               "        cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "    results.append(other)\n")
        t3p = ("    box = {\"row\": {}}\n"
               "    a = {\"row\": {}}\n"
               "    dummy, cp = (a := box), a.copy()\n"
               "    cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "    results.append(box)\n")
        cases = [
            ("t1p-prelude-reshare",
             [(prelude, prelude + t1p)]),
            ("t3p-copy-after-walrus",
             [(prelude, prelude + t3p)]),
        ]
        fragment = "tainted path escapes to results.append()"
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r28_placed_shapes(self):
        # adjudication-r27 silent placements: the
        # prelude endpoint rebind (T2p — the rebound
        # edge names the pairing-time object, so the
        # fresh box stays clean) and the module-home
        # copy through a global (T6 — the nested store
        # resolves in the module binds, where no box
        # alias exists).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        cases = [
            ("t2p-prelude-endpoint-rebind",
             [(prelude,
               prelude + "    box = {}\n"
               "    for i in range(2):\n"
               "        a = box\n"
               "        box = {}\n"
               "        a[\"raw\"] = log\n"
               "    results.append(box)\n")]),
            ("t6-module-home",
             [(mod, "a_t6probe = {}\n" + mod),
              (anchor,
               head + "            box = {}\n"
               "            a_t6probe = box\n"
               "            def f():\n"
               "                global a_t6probe\n"
               "                b = a_t6probe\n"
               "                b[\"raw\"] = log\n"
               "            f()\n"
               "            results.append(box)\n"
               + use)]),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r29_plants(self):
        # adjudication-r28 W-fixes, anchor placement:
        # per-target walrus/store order (W5), nested
        # walrus completion in capability resolution
        # (W6) and alias replay (W6a).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        sunk = "tainted path escapes to results.append()"
        fire = [
            ("w5-target-walrus-order",
             [(anchor,
               head + "            def clean(self):\n"
               "                return None\n"
               "            rb = clean\n"
               "            container = {}\n"
               "            rb, container[(rb := Path.read_bytes)] = "
               "clean, None\n"
               "            Path.r = rb\n"
               "            ignored = decode_body_log(log.r())\n"
               + use)],
             "tainted path escapes to log.r()"),
            ("w6-nested-walrus-order",
             [(anchor,
               head + "            def clean(self):\n"
               "                return None\n"
               "            rb = Path.read_bytes\n"
               "            dummy = (rb := ((rb := clean), "
               "Path.read_bytes)[1])\n"
               "            Path.r = rb\n"
               "            ignored = decode_body_log(log.r())\n"
               + use)],
             "tainted path escapes to log.r()"),
            ("w6a-nested-walrus-alias",
             [(anchor,
               head + "            box = {}\n"
               "            other = {}\n"
               "            a = other\n"
               "            dummy = (z := ((a := box), {})[0])\n"
               "            a[\"raw\"] = log\n"
               "            results.append(box)\n"
               + use)],
             sunk),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_catches_r29_prelude_plants(self):
        # adjudication-r28 W-fixes, prelude placement:
        # same-statement copy/rebind order (W1),
        # load-retaining fresh displays (W3/W3b/W3d1),
        # receiver-walrus copies (W4), class early
        # stores (W8, needs its module plant),
        # starred element stores (W9) and prefix
        # pairing incl. unequal splats (W10/W10c).
        # w3c1 pins a documented fail-closed FP
        # (key-only splats cannot disconnect
        # without type information).
        source = Path(lane.__file__).read_text()
        mod = "def execute("
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        cases = [
            ("w1-same-statement-copy-rebind",
             [(prelude,
               prelude + "    box = {\"row\": {}}\n"
               "    other = {\"row\": {}}\n"
               "    for i in range(2):\n"
               "        cp, box = box.copy(), other\n"
               "        cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "    results.append(other)\n")]),
            ("w3-fresh-keeps-old-ref",
             [(prelude,
               prelude + "    box = {}\n"
               "    for i in range(2):\n"
               "        a = box\n"
               "        box = {\"old\": box}\n"
               "        a[\"raw\"] = log\n"
               "    results.append(box)\n")]),
            ("w3b-dict-comp-wraps-old",
             [(prelude,
               prelude + "    box = {}\n"
               "    for i in range(2):\n"
               "        a = box\n"
               "        box = {i: box for i in range(1)}\n"
               "        a[\"raw\"] = log\n"
               "    results.append(box)\n")]),
            ("w3d1-splat-values-single",
             [(prelude,
               prelude + "    box = {\"row\": {}}\n"
               "    for i in range(1):\n"
               "        a = box\n"
               "        box = [*box.values()]\n"
               "        a[\"row\"][\"raw\"] = f\"{log}\"\n"
               "    results.append(box)\n")]),
            ("w3c1-splat-keys-single-fp",
             [(prelude,
               prelude + "    box = {}\n"
               "    for i in range(1):\n"
               "        a = box\n"
               "        box = [*box]\n"
               "        a[\"raw\"] = log\n"
               "    results.append(box)\n")]),
            ("w4-receiver-walrus-copy",
             [(prelude,
               prelude + "    box = {\"row\": {}}\n"
               "    a = {\"row\": {}}\n"
               "    dummy = (cp := (a := box).copy())\n"
               "    cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "    results.append(box)\n")]),
            ("w8-class-early-store",
             [(mod, "m_cls = {}\na_cls = m_cls\n" + mod),
              (prelude,
               prelude + "    class C:\n"
               "        a_cls[\"raw\"] = log\n"
               "        a_cls = {}\n"
               "    results.append(m_cls)\n")]),
            ("w9-starred-element-store",
             [(prelude,
               prelude + "    box = {}\n"
               "    *a, b = box, {}\n"
               "    a[0][\"raw\"] = log\n"
               "    results.append(box)\n")]),
            ("w10-starred-prefix-pair",
             [(prelude,
               prelude + "    box = {}\n"
               "    a, *rest = box, {}, {}\n"
               "    a[\"raw\"] = log\n"
               "    results.append(box)\n")]),
            ("w10c-starred-unequal-splat",
             [(prelude,
               prelude + "    box = {}\n"
               "    a, *rest = *[box, {}], {}\n"
               "    a[\"raw\"] = log\n"
               "    results.append(box)\n")]),
        ]
        fragment = "tainted path escapes to results.append()"
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r29_prelude_shapes(self):
        # adjudication-r28 silent placements: the
        # same-statement fresh divorce (W1b — the old
        # object is garbage when the seed is
        # unaliased), the for-target separator (W2),
        # in-scope kills before the store (W7 class,
        # W7b func) and the starred top-store control
        # (W9b).
        source = Path(lane.__file__).read_text()
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        cases = [
            ("w1b-same-statement-fresh-divorce",
             [(prelude,
               prelude + "    box = {\"row\": {}}\n"
               "    for i in range(2):\n"
               "        box, cp = {\"row\": {}}, box.copy()\n"
               "        cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "    results.append(box)\n")]),
            ("w2-for-target-separator",
             [(prelude,
               prelude + "    other = {\"row\": {}}\n"
               "    for box in ({\"row\": {}}, {\"row\": {}}):\n"
               "        cp = box.copy()\n"
               "        box = other\n"
               "        cp[\"row\"][\"raw\"] = f\"{log}\"\n"
               "    results.append(other)\n")]),
            ("w7-class-scope-kill",
             [(prelude,
               prelude + "    box = {}\n"
               "    class C:\n"
               "        a = box\n"
               "        a = {}\n"
               "        a[\"raw\"] = log\n"
               "    results.append(box)\n")]),
            ("w7b-func-scope-kill",
             [(prelude,
               prelude + "    box = {}\n"
               "    def outer():\n"
               "        a = box\n"
               "        a = {}\n"
               "        def inner():\n"
               "            a[\"raw\"] = log\n"
               "        inner()\n"
               "    outer()\n"
               "    results.append(box)\n")]),
            ("w9b-starred-top-control",
             [(prelude,
               prelude + "    box = {}\n"
               "    other = {}\n"
               "    *a, b = box, other\n"
               "    a[0] = log\n"
               "    results.append(box)\n")]),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r30_plants(self):
        # adjudication-r29 X-fixes: retained-descendant
        # divorce guards (X1/X1b/X1c) incl. conditional
        # batches (X1e), reinstalling loop headers
        # (X2/X2b), per-leaf completion order (X4/X4c),
        # same-object kills (X5/X5b/X5c/X5d),
        # class-namespace module fallback (X6), starred
        # element union (X7/X7b), star depth (X8b) and
        # target order (X9/X9b).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ('x1-divorce-surviving-copy',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            keep = box.copy()\n'
                     '            cp, box = box.copy(), {}\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(keep)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x1b-divorce-same-batch-alias',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            cp, box, y = box.copy(), {}, box\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(y)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x1c-divorce-earlier-append',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            keep = box.copy()\n'
                     '            cp, box = box.copy(), {}\n'
                     '            results.append(keep)\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x2-aliasing-header',
             [
              (anchor,
               head + '            other = {"row": {}}\n'
                     '            for box in (other, other):\n'
                     '                cp = box.copy()\n'
                     '                box = other\n'
                     '                cp["row"]["raw"] = f"{log}"\n'
                     '            results.append(other)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x2b-destructured-header',
             [
              (anchor,
               head + '            other = {"row": {}}\n'
                     '            for box, _ in ((other, 1), (other, 2)):\n'
                     '                cp = box.copy()\n'
                     '                box = other\n'
                     '                cp["row"]["raw"] = f"{log}"\n'
                     '            results.append(other)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x4-duplicate-targets',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return None\n'
                     '            rb = clean\n'
                     '            container = {}\n'
                     '            rb, container[(rb := clean)], rb = clean, '
                     'None, Path.read_bytes\n'
                     '            Path.r = rb\n'
                     '            ignored = decode_body_log(log.r())\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('x4c-nested-tuple-targets',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return None\n'
                     '            rb = clean\n'
                     '            container = {}\n'
                     '            (rb, container[(rb := clean)]), rb = '
                     '(clean, None), Path.read_bytes\n'
                     '            Path.r = rb\n'
                     '            ignored = decode_body_log(log.r())\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('x5-self-alias-kill',
             [
              (anchor,
               head + '            box = {}\n'
                     '            class C:\n'
                     '                a = box\n'
                     '                a = a\n'
                     '                a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x5b-peer-cycle-kill',
             [
              (anchor,
               head + '            box = {}\n'
                     '            class C:\n'
                     '                a = box\n'
                     '                b = a\n'
                     '                a = b\n'
                     '                a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x5c-decorated-def-kill',
             [
              (anchor,
               head + '            box = {}\n'
                     '            class C:\n'
                     '                a = box\n'
                     '                @(lambda f: box)\n'
                     '                def a():\n'
                     '                    pass\n'
                     '                a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x5d-func-self-alias',
             [
              (anchor,
               head + '            box = {}\n'
                     '            def outer():\n'
                     '                a = box\n'
                     '                a = a\n'
                     '                def inner():\n'
                     '                    a["raw"] = log\n'
                     '                inner()\n'
                     '            outer()\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x6-enclosing-local-fallback',
             [
              (mod,
               'm_cls = {}\n'
               'a_cls = m_cls\n'
               + mod),
              (anchor,
               head + '            a_cls = {}\n'
                     '            class C:\n'
                     '                a_cls["raw"] = log\n'
                     '                a_cls = {}\n'
                     '            results.append(m_cls)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x7-starred-first-element',
             [
              (anchor,
               head + '            box = {}\n'
                     '            other = {}\n'
                     '            *xs, = [box, other]\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x7b-starred-last-element',
             [
              (anchor,
               head + '            box = {}\n'
                     '            other = {}\n'
                     '            *xs, = [other, box]\n'
                     '            xs[1]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x8b-starred-nested-display',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [[box]]\n'
                     '            xs[0][0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x9-starred-suffix-order',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *a, a = [{}, box]\n'
                     '            a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x9b-starred-empty-suffix',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *a, a = [box]\n'
                     '            a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('x1e-conditional-batch-no-divorce',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            cp = box.copy()\n'
                     '            if flag:\n'
                     '                cp, box = box.copy(), {}\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r30_shapes(self):
        # adjudication-r29 X-fixes, silent placements:
        # the unretained divorce (X1d), load-free
        # tuples/comprehensions (X3/X3b), the
        # duplicate-target clean final (X4b),
        # alias-to-foreign kills (X5e), the class-local
        # inverse (X6b), copy-top star stores (X8), the
        # fresh suffix (X9c) and nested param/local
        # shadows (X10/X10b).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        mod = "def execute("
        cases = [
            ('x1d-earlier-append-box',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            cp, box = box.copy(), {}\n'
                     '            results.append(box)\n'
                     '            cp["row"]["raw"] = log\n'
               + use),
             ]),
            ('x3-tuple-display',
             [
              (prelude,
               prelude + '    box = {"row": {}}\n'
                        '    for i in range(1):\n'
                        '        a = box\n'
                        '        box = {"x": (0,)}\n'
                        '        a["row"]["raw"] = log\n'
                        '    results.append(box)\n'
               ),
             ]),
            ('x3b-comprehension-stores',
             [
              (prelude,
               prelude + '    box = {"row": {}}\n'
                        '    for i in range(1):\n'
                        '        a = box\n'
                        '        box = [0 for _ in [0]]\n'
                        '        a["row"]["raw"] = log\n'
                        '    results.append(box)\n'
               ),
             ]),
            ('x4b-duplicate-targets-inverse',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return None\n'
                     '            rb = Path.read_bytes\n'
                     '            container = {}\n'
                     '            rb, container[(rb := Path.read_bytes)], rb '
                     '= Path.read_bytes, None, clean\n'
                     '            Path.r = rb\n'
                     '            ignored = decode_body_log(log.r())\n'
               + use),
             ]),
            ('x6b-enclosing-local-inverse',
             [
              (mod,
               'm_cls = {}\n'
               'a_cls = {}\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                a_cls["raw"] = log\n'
                     '                a_cls = {}\n'
                     '            results.append(box)\n'
               + use),
             ]),
            ('x8-starred-copy-depth',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            *xs, = [box.copy()]\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ]),
            ('x9c-starred-suffix-clean',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *a, a = [box, {"row": {}}]\n'
                     '            a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ]),
            ('x10-param-shadow-taint',
             [
              (anchor,
               head + '            box = {}\n'
                     '            def f(box):\n'
                     '                box["raw"] = log\n'
                     '            f({})\n'
                     '            results.append(box)\n'
               + use),
             ]),
            ('x10b-param-renamed-control',
             [
              (anchor,
               head + '            box = {}\n'
                     '            def f(a):\n'
                     '                a["raw"] = log\n'
                     '            f({})\n'
                     '            results.append(box)\n'
               + use),
             ]),
            ('x5e-alias-to-foreign-kills',
             [
              (anchor,
               head + '            box = {}\n'
                     '            other = {}\n'
                     '            class C:\n'
                     '                a = box\n'
                     '                a = other\n'
                     '                a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ]),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r31_plants(self):
        # adjudication-r30 Y-fixes: same-batch walrus
        # retainers (Y1/Y1b), nested/chained target order
        # (Y3/Y3b), saved-alias restores (Y4), inherited
        # metaclasses (Y5), class freevars (Y6), star
        # aliases/copies/chains (Y7/Y7b/Y7c), nested and
        # class star binds (Y8/Y8b), splice/unpack depth
        # (Y9/Y9b) and observing nested sinks
        # (Y11/Y11b).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ('y1-target-walrus-retainer',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            sink = {}\n'
                     '            cp, sink[((keep := box), 0)[1]], box = box.copy(), 0, {}\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(keep)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y1b-target-walrus-copy',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            sink = {}\n'
                     '            cp, sink[((keep := box.copy()), 0)[1]], box = box.copy(), 0, {}\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(keep)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y3-nested-target-order',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return None\n'
                     '            rb = clean\n'
                     '            container = {}\n'
                     '            ((rb, container[(rb := Path.read_bytes)]),) = ((clean, None),)\n'
                     '            Path.r = rb\n'
                     '            ignored = decode_body_log(log.r())\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('y3b-chained-target-order',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return None\n'
                     '            rb = clean\n'
                     '            container = {}\n'
                     '            rb, rb = container[(rb := Path.read_bytes)] = (clean, clean)\n'
                     '            Path.r = rb\n'
                     '            ignored = decode_body_log(log.r())\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('y4-saved-alias-restore',
             [
              (anchor,
               head + '            box = {}\n'
                     '            class C:\n'
                     '                a = box\n'
                     '                b = a\n'
                     '                a = {}\n'
                     '                a = b\n'
                     '                a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y5-inherited-metaclass',
             [
              (anchor,
               head + '            box = {}\n'
                     '            class Meta(type):\n'
                     '                def __new__(mcls, name, bases, ns):\n'
                     '                    if name == "a":\n'
                     '                        return box\n'
                     '                    return super().__new__(mcls, name, bases, ns)\n'
                     '            class Base(metaclass=Meta):\n'
                     '                pass\n'
                     '            class C:\n'
                     '                a = box\n'
                     '                class a(Base):\n'
                     '                    pass\n'
                     '                a["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y6-class-freevar',
             [
              (mod,
               'a_cls = {}\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                a_cls["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y7-star-alias',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            ys = xs\n'
                     '            ys[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y7b-star-copy',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            ys = xs.copy()\n'
                     '            ys[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y7c-star-chain',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            ys = xs\n'
                     '            zs = ys\n'
                     '            zs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y8-nested-star',
             [
              (anchor,
               head + '            box = {}\n'
                     '            def f():\n'
                     '                *xs, = [box]\n'
                     '                xs[0]["raw"] = log\n'
                     '            f()\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y8b-class-star',
             [
              (anchor,
               head + '            box = {}\n'
                     '            class C:\n'
                     '                *xs, = [box]\n'
                     '                xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y9-splice-depth',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [[*[box]]]\n'
                     '            xs[0][0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y9b-unpack-depth',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [{**{"slot": box}}]\n'
                     '            xs[0]["slot"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y11-nested-local-sink',
             [
              (anchor,
               head + '            def f():\n'
                     '                box = {}\n'
                     '                box["raw"] = log\n'
                     '                results.append(box)\n'
                     '            f()\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('y11b-nested-open-sink',
             [
              (anchor,
               head + '            def f():\n'
                     '                box = {}\n'
                     '                box["raw"] = log\n'
                     '                open(box["raw"])\n'
                     '            f()\n'
               + use),
             ],
             'tainted path escapes to open()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r31_shapes(self):
        # adjudication-r30 Y-fixes, silent placements:
        # generator captures (Y2/Y2b), the module-alias
        # inverse (Y6b) and rebased star captures
        # (Y10/Y10b).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        mod = "def execute("
        cases = [
            ('y2-generator-capture',
             [
              (prelude,
               prelude + '    box = {"row": {}}\n'
                        '    for i in range(1):\n'
                        '        a = box\n'
                        '        box = {"g": (0 for _ in (0,) if (a := True))}\n'
                        '        a["row"]["raw"] = log\n'
                        '        results.append({"saved": box["g"].gi_frame.f_locals["a"]})\n'),
             ],
             ),
            ('y2b-generator-direct-append',
             [
              (prelude,
               prelude + '    box = {"row": {}}\n'
                        '    for i in range(1):\n'
                        '        a = box\n'
                        '        box = {"g": (0 for _ in (0,) if (a := True))}\n'
                        '        a["row"]["raw"] = log\n'
                        '    results.append(box)\n'),
             ],
             ),
            ('y6b-module-alias-inverse',
             [
              (mod,
               'box = {}\n'
                     'a_cls = box\n'
               + mod),
              (anchor,
               head + '            a_cls = {}\n'
                     '            class C:\n'
                     '                a_cls["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             ),
            ('y10-star-rebind',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            xs = [{}]\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             ),
            ('y10b-captured-identity',
             [
              (anchor,
               head + '            box = {}\n'
                     '            other = {}\n'
                     '            *xs, = [box]\n'
                     '            box = other\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(other)\n'
               + use),
             ],
             ),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r32_plants(self):
        # adjudication-r31 Z-fixes: repeated chained
        # targets (Z1), depth-aware prune (Z2), star
        # own-copy provenance (Z3), graft installation
        # times (Z4/Z4b/Z4c), pass invariance (Z5),
        # annotation-only class locals (Z6), home
        # observation via local alias (Z7) and mixed
        # dict unpack values (Z8).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ('z1-repeated-chained-targets',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return b"clean"\n'
                     '            rb = clean\n'
                     '            container = {}\n'
                     '            rb, rb = container[(rb := clean)] = rb, rb = (\n'
                     '                Path.read_bytes, Path.read_bytes)\n'
                     '            Path.r = rb\n'
                     '            ignored = decode_body_log(log.r())\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('z2-prune-shallow-copy-rebind',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            *xs, = [box]\n'
                     '            box = box.copy()\n'
                     '            xs[0]["row"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z3-star-own-copy',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            xs = xs.copy()\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z4-graft-alias-chain',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            saved = box\n'
                     '            new = saved\n'
                     '            box = {}\n'
                     '            saved = {}\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(new)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z4b-graft-conditional-rebind',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            if False:\n'
                     '                box = {}\n'
                     '            saved = box\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(saved)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z4c-full-conditional',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            if False:\n'
                     '                box = {}\n'
                     '            saved = box\n'
                     '            new = saved\n'
                     '            box = {}\n'
                     '            saved = {}\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(new)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z5-loop-invariance',
             [
              (anchor,
               head + '            other = {}\n'
                     '            sink = {}\n'
                     '            for i in range(2):\n'
                     '                box = other\n'
                     '                *xs, = [box]\n'
                     '                other = sink\n'
                     '                xs[0]["raw"] = log\n'
                     '            results.append(sink)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z6-annotation-class-local',
             [
              (mod,
               'module_box = {}\n'
                     'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                a_cls: object\n'
                     '                a_cls["raw"] = log\n'
                     '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z7-home-local-alias',
             [
              (anchor,
               head + '            def f():\n'
                     '                box = {}\n'
                     '                box["raw"] = log\n'
                     '                saved = box\n'
                     '                results.append(saved)\n'
                     '            f()\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('z8-mixed-dict-unpack',
             [
              (anchor,
               head + '            box = {}\n'
                     '            empty = {}\n'
                     '            *xs, = [{**empty, "slot": box}]\n'
                     '            xs[0]["slot"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r32_shapes(self):
        # adjudication-r31 Z-fixes, silent placements:
        # the swapped-targets inverse (Z1b), the
        # annotation inverse (Z6b), dead alias
        # candidates (Z9), nested depth reuse (Z10)
        # and the post-rebind walrus (Z11).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        prelude = "    _CANCELLATION_REAP_FAILED = False\n"
        mod = "def execute("
        cases = [
            ('z1b-swapped-targets',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return b"clean"\n'
                     '            rb = Path.read_bytes\n'
                     '            container = {}\n'
                     '            rb, rb = container[(rb := Path.read_bytes)] = rb, rb = (\n'
                     '                clean, clean)\n'
                     '            Path.r = rb\n'
                     '            ignored = decode_body_log(log.r())\n'
               + use),
             ],
             ),
            ('z6b-annotation-inverse',
             [
              (mod,
               'module_box = {}\n'
                     'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                a_cls: object\n'
                     '                a_cls["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             ),
            ('z9-dead-alias-candidate',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            ys = xs\n'
                     '            ys = [{}]\n'
                     '            ys[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             ),
            ('z10-nested-depth-reuse',
             [
              (anchor,
               head + '            box = {}\n'
                     '            def f():\n'
                     '                cp = box.copy()\n'
                     '                *xs, = [cp]\n'
                     '                xs[0]["raw"] = log\n'
                     '            f()\n'
                     '            results.append(box)\n'
               + use),
             ],
             ),
            ('z11-walrus-after-rebind',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            sink = {}\n'
                     '            cp, box, sink[((keep := box), 0)[1]] = box.copy(), {}, 0\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(keep)\n'
               + use),
             ],
             ),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r33_plants(self):
        # adjudication-r32 A-fixes: declared class
        # locals across deletion (A1), restoration-
        # aware grafts (A4), depth-preserving copy
        # breaks (A5), overwritten resets (A6),
        # element-preserving unpacks (A7), copy-
        # wrapped mixed dicts (A8) and nested RHS
        # walruses (A10).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ('a1-class-del-crash',
             [
              (mod,
               'module_box = {}\n'
                     'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                a_cls = box\n'
                     '                del a_cls\n'
                     '                a_cls["raw"] = log\n'
                     '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('a4-graft-restore',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            a = box\n'
                     '            a = {}\n'
                     '            a = box\n'
                     '            b = a\n'
                     '            box = {}\n'
                     '            a = {}\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(b)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('a5-graft-copy-break',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            *xs, = [box]\n'
                     '            box = box.copy()\n'
                     '            saved = box\n'
                     '            box = {}\n'
                     '            xs[0]["row"]["raw"] = log\n'
                     '            results.append(saved)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('a6-overwritten-reset',
             [
              (anchor,
               head + '            other = {}\n'
                     '            sink = {}\n'
                     '            for i in range(2):\n'
                     '                box = {}\n'
                     '                box = other\n'
                     '                *xs, = [box]\n'
                     '                other = sink\n'
                     '                xs[0]["raw"] = log\n'
                     '            results.append(sink)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('a7-unpack-self-copy',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            xs = [*xs]\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('a8-copy-wrapped-mixed-dict',
             [
              (anchor,
               head + '            box = {}\n'
                     '            empty = {}\n'
                     '            *xs, = [({**empty, "slot": box}).copy()]\n'
                     '            xs[0]["slot"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('a10-nested-rhs-walrus',
             [
              (anchor,
               head + '            def clean(self):\n'
                     '                return b"CLEAN"\n'
                     '            def f():\n'
                     '                rb = clean\n'
                     '                rb, rb = ((review_cap_value := Path.read_bytes), review_cap_value)\n'
                     '                Path.r = rb\n'
                     '                ignored = decode_body_log(log.r())\n'
                     '                results.append(ignored)\n'
                     '            f()\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r33_shapes(self):
        # adjudication-r32 A-fixes, silent placements:
        # the deletion-only control (A1b), self-
        # copies after a fresh rebind (A2), stale
        # alias identity (A3), the depth-1 copy-
        # break control (A5b) and source walruses
        # stored before the retainer (A9).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        cases = [
            ('a1b-del-only',
             [
              (mod,
               'module_box = {}\n'
                     'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                del a_cls\n'
                     '                a_cls["raw"] = log\n'
                     '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('a2-copy-after-fresh',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            *xs, = [box]\n'
                     '            box = {"row": {}}\n'
                     '            box = box.copy()\n'
                     '            xs[0]["row"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             ),
            ('a3-stale-alias-identity',
             [
              (anchor,
               head + '            box = {}\n'
                     '            other = box\n'
                     '            other = {}\n'
                     '            *xs, = [box]\n'
                     '            box = other\n'
                     '            saved = box\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(saved)\n'
               + use),
             ],
             ),
            ('a5b-copy-break-depth1',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            *xs, = [box]\n'
                     '            box = box.copy()\n'
                     '            saved = box\n'
                     '            box = {}\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(saved)\n'
               + use),
             ],
             ),
            ('a9-walrus-store-before-retainer',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            sink = {}\n'
                     '            cp, sink[((box := {}), 2)[1]], sink[((keep := box), 0)[1]], box = box.copy(), 0, 0, {}\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(keep)\n'
               + use),
             ],
             ),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r34_plants(self):
        # adjudication-r33 B-fixes: per-operand favor
        # (B1), completion-ordered nested walrus stores
        # (B2), caught deletions with module fallback
        # (B5/B5b), conditional restorations (B6),
        # nested unpack compositions (B7/B7b) and
        # nested copy displays (B8/B8b).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        clean = ('            def clean(self):\n'
                 '                return b"CLEAN"\n')
        fire = [
            ('b1-rhs-favor-late-effect',
             [
              (anchor,
               head + clean
                     + '            def f():\n'
                     '                w = Path.read_bytes\n'
                     '                rb, ignored = w, (w := clean)\n'
                     '                Path.r = rb\n'
                     '                ignored = decode_body_log(log.r())\n'
                     '                results.append(ignored)\n'
                     '            f()\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('b2-nested-target-walrus',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            sink = {}\n'
                     '            cp, sink[((box := (box, (box := {}))[0]), 0)[1]], sink[((keep := box), 1)[1]], box = box.copy(), 0, 0, {}\n'
                     '            cp["row"]["raw"] = log\n'
                     '            results.append(keep)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('b5-caught-del',
             [
              (mod,
               'module_box = {}\n'
                     'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                try:\n'
                     '                    del a_cls\n'
                     '                except NameError:\n'
                     '                    pass\n'
                     '                a_cls["raw"] = log\n'
                     '                a_cls = box\n'
                     '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('b5b-caught-del-no-install',
             [
              (mod,
               'module_box = {}\n'
                     'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     '            a_cls = box\n'
                     '            class C:\n'
                     '                try:\n'
                     '                    del a_cls\n'
                     '                except NameError:\n'
                     '                    pass\n'
                     '                a_cls["raw"] = log\n'
                     '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('b6-conditional-restore',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            a = box\n'
                     '            a = {}\n'
                     '            if True:\n'
                     '                a = box\n'
                     '            b = a\n'
                     '            box = {}\n'
                     '            a = {}\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(b)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('b7-nested-unpack',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            xs = [*[*xs]]\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('b7b-nested-tuple-unpack',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            xs = (*(*xs,),)\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('b8-nested-copy-display',
             [
              (anchor,
               head + '            box = {}\n'
                     '            empty = {}\n'
                     '            *xs, = [dict(({**empty, "slot": box}).copy())]\n'
                     '            xs[0]["slot"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('b8b-dict-dict',
             [
              (anchor,
               head + '            box = {}\n'
                     '            empty = {}\n'
                     '            *xs, = [dict(dict(empty, **{"slot": box}))]\n'
                     '            xs[0]["slot"]["raw"] = log\n'
                     '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r34_shapes(self):
        # adjudication-r33 B-fixes, silent placements:
        # the early-walrus (B1b), walrus-first-target
        # (B1c) and clean-prebind (B1d) favor
        # controls, restoration through rebound-away
        # spellings at depths 1-3 (B3/B3b/B3c) and
        # overwritten resets (B4/B4b for/while).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        clean = ('            def clean(self):\n'
                 '                return b"CLEAN"\n')
        cases = [
            ('b1b-inverted-early-walrus',
             [
              (anchor,
               head + clean
                     + '            def f():\n'
                     '                w = Path.read_bytes\n'
                     '                ignored, rb = (w := clean), w\n'
                     '                Path.r = rb\n'
                     '                ignored = decode_body_log(log.r())\n'
                     '                results.append(ignored)\n'
                     '            f()\n'
               + use),
             ],
             ),
            ('b1c-walrus-first-target',
             [
              (anchor,
               head + clean
                     + '            def f():\n'
                     '                w = Path.read_bytes\n'
                     '                rb, ignored = (w := clean), w\n'
                     '                Path.r = rb\n'
                     '                ignored = decode_body_log(log.r())\n'
                     '                results.append(ignored)\n'
                     '            f()\n'
               + use),
             ],
             ),
            ('b1d-clean-prebind-late-reader',
             [
              (anchor,
               head + clean
                     + '            def f():\n'
                     '                w = clean\n'
                     '                rb, ignored = w, (w := Path.read_bytes)\n'
                     '                Path.r = rb\n'
                     '                ignored = decode_body_log(log.r())\n'
                     '                results.append(ignored)\n'
                     '            f()\n'
               + use),
             ],
             ),
            ('b3-restoration-fresh-rejoin',
             [
              (anchor,
               head + '            box = {}\n'
                     '            *xs, = [box]\n'
                     '            a = box\n'
                     '            box = {}\n'
                     '            a = box\n'
                     '            b = a\n'
                     '            xs[0]["raw"] = log\n'
                     '            results.append(b)\n'
               + use),
             ],
             ),
            ('b3b-restoration-depth2',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     '            *xs, = [box]\n'
                     '            a = box\n'
                     '            box = {"row": {}}\n'
                     '            a = box\n'
                     '            b = a\n'
                     '            xs[0]["row"]["raw"] = log\n'
                     '            results.append(b)\n'
               + use),
             ],
             ),
            ('b3c-restoration-depth3',
             [
              (anchor,
               head + '            box = {"row": {"cell": {}}}\n'
                     '            *xs, = [box]\n'
                     '            a = box\n'
                     '            box = {"row": {"cell": {}}}\n'
                     '            a = box\n'
                     '            b = a\n'
                     '            xs[0]["row"]["cell"]["raw"] = log\n'
                     '            results.append(b)\n'
               + use),
             ],
             ),
            ('b4-overwritten-reset',
             [
              (anchor,
               head + '            other = {}\n'
                     '            sink = {}\n'
                     '            for i in range(2):\n'
                     '                box = other\n'
                     '                box = {}\n'
                     '                *xs, = [box]\n'
                     '                other = sink\n'
                     '                xs[0]["raw"] = log\n'
                     '            results.append(sink)\n'
               + use),
             ],
             ),
            ('b4b-overwritten-while',
             [
              (anchor,
               head + '            other = {}\n'
                     '            sink = {}\n'
                     '            i = 0\n'
                     '            while i < 2:\n'
                     '                box = other\n'
                     '                box = {}\n'
                     '                *xs, = [box]\n'
                     '                other = sink\n'
                     '                xs[0]["raw"] = log\n'
                     '                i += 1\n'
                     '            results.append(sink)\n'
               + use),
             ],
             ),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r35_plants(self):
        # adjudication-r34 C-fixes, firing placements:
        # the catching-tuple control (C1d), the
        # handler-mutation control (C2c), the
        # finally-mutation positive (C3), dict
        # pair iterables (C4/C4b), named-mapping
        # chains (C6/C6b/C6c), set displays
        # (C7/C7b) and the other-index control
        # (C11b).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ('c1d-except-tuple-catching',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                except (NameError, ValueError):\n'
                     + '                    pass\n'
                     + '                a_cls["raw"] = log\n'
                     + '                a_cls = box\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c2c-mutation-in-handler',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                except NameError:\n'
                     + '                    a_cls["raw"] = log\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c3-finally-mutation',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            try:\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    finally:\n'
                     + '                        a_cls["raw"] = log\n'
                     + '            except NameError:\n'
                     + '                pass\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c4-dict-pairs-list',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [dict([("slot", box)], extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c4b-dict-pairs-tuple',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [dict((("slot", box),), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c6-named-mapping-chain',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            *xs, = [dict(dict(mapping.copy(), extra={})).copy().copy()]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c6b-named-mapping-small',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c6c-named-mapping-d2',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["row"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c7-set-display',
             [
              (mod,
               'class HashDict(dict):\n'
               '    __hash__ = object.__hash__\n'
               + mod),
              (anchor,
               head + '            box = HashDict()\n'
                     + '            *xs, = [list(set({box}))]\n'
                     + '            xs[0][0]["raw"] = log\n'
                     + '            results.append({"payload": box})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c7b-set-copy',
             [
              (mod,
               'class HashDict(dict):\n'
               '    __hash__ = object.__hash__\n'
               + mod),
              (anchor,
               head + '            box = HashDict()\n'
                     + '            *xs, = [list(({box}).copy())]\n'
                     + '            xs[0][0]["raw"] = log\n'
                     + '            results.append({"payload": box})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('c11b-other-index-replace',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            other = {}\n'
                     + '            *xs, = [box, other]\n'
                     + '            xs = [*[*xs]]\n'
                     + '            xs[1] = {}\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r35_shapes(self):
        # adjudication-r34 C-fixes, silent placements:
        # LookupError narrowing (C1/C1b/C1c),
        # try-body/else del replay (C2/C2b),
        # uncaught-finally silence (C3b), kwarg
        # overwrite (C5/C5b/C5c), conditional
        # non-restore pruning (C8/C8b/C8c), the
        # dead self-alias (C9), the unfinished
        # enclosing walrus (C10) and element
        # replacement (C11).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        cases = [
            ('c1-except-lookuperror',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                except LookupError:\n'
                     + '                    pass\n'
                     + '                a_cls["raw"] = log\n'
                     + '                a_cls = box\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('c1b-except-dotted-lookuperror',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                except builtins.LookupError:\n'
                     + '                    pass\n'
                     + '                a_cls["raw"] = log\n'
                     + '                a_cls = box\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('c1c-except-tuple-disjoint',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                except (LookupError, ValueError):\n'
                     + '                    pass\n'
                     + '                a_cls["raw"] = log\n'
                     + '                a_cls = box\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('c2-mutation-in-try-body',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                    a_cls["raw"] = log\n'
                     + '                except NameError:\n'
                     + '                    pass\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('c2b-mutation-in-else',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                except NameError:\n'
                     + '                    pass\n'
                     + '                else:\n'
                     + '                    a_cls["raw"] = log\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('c3b-finally-uncaught',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                finally:\n'
                     + '                    a_cls["raw"] = log\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('c5-kwarg-override',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [dict({"slot": box}, slot={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('c5b-kwarg-override-d2',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     + '            *xs, = [dict({"slot": box}, slot={})]\n'
                     + '            xs[0]["slot"]["row"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('c5c-kwarg-override-d3',
             [
              (anchor,
               head + '            box = {"row": {"cell": {}}}\n'
                     + '            *xs, = [dict({"slot": box}, slot={})]\n'
                     + '            xs[0]["slot"]["row"]["cell"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('c8-conditional-nonrestore',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            a = box\n'
                     + '            box = {}\n'
                     + '            a = {}\n'
                     + '            if True:\n'
                     + '                a = box\n'
                     + '            b = a\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(b)\n'
               + use),
             ],
             ),
            ('c8b-conditional-nonrestore-d2',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     + '            *xs, = [box]\n'
                     + '            a = box\n'
                     + '            box = {"row": {}}\n'
                     + '            a = {}\n'
                     + '            if True:\n'
                     + '                a = box\n'
                     + '            b = a\n'
                     + '            xs[0]["row"]["raw"] = log\n'
                     + '            results.append(b)\n'
               + use),
             ],
             ),
            ('c8c-conditional-nonrestore-d3',
             [
              (anchor,
               head + '            box = {"row": {"cell": {}}}\n'
                     + '            *xs, = [box]\n'
                     + '            a = box\n'
                     + '            box = {"row": {"cell": {}}}\n'
                     + '            a = {}\n'
                     + '            if True:\n'
                     + '                a = box\n'
                     + '            b = a\n'
                     + '            xs[0]["row"]["cell"]["raw"] = log\n'
                     + '            results.append(b)\n'
               + use),
             ],
             ),
            ('c9-transient-self-alias',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     + '            sink = {}\n'
                     + '            cp, sink[(((box := box), (box := {})), 0)[1]], sink[((keep := box), 1)[1]], box = box.copy(), 0, 0, {}\n'
                     + '            cp["row"]["raw"] = log\n'
                     + '            results.append(keep)\n'
               + use),
             ],
             ),
            ('c10-unfinished-enclosing-walrus',
             [
              (anchor,
               head + '            def clean(self):\n'
                     + '                return b"CLEAN"\n'
                     + '            def f():\n'
                     + '                w = clean\n'
                     + '                ignored = (w := ((rb := w), Path.read_bytes)[1])\n'
                     + '                Path.r = rb\n'
                     + '                ignored = decode_body_log(log.r())\n'
                     + '                results.append(ignored)\n'
                     + '            f()\n'
               + use),
             ],
             ),
            ('c11-element-replace-after-unpack',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            xs = [*[*xs]]\n'
                     + '            xs[0] = {}\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r36_plants(self):
        # adjudication-r35 D-fixes, firing placements:
        # reachable publishes (D1a/D1b), the rebound
        # builtins handler (D2), restoration-time
        # liveness (D3), the skipped fresh walrus
        # (D4), index-shift invalidations (D5a/D5b),
        # same-statement order (D6), duplicate
        # indexed targets incl. the documented-FP
        # reversed control (D7/D7b), the nested
        # skipped install (D8) and the for-iterator
        # late store (D9).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ('d1a-dead-publish-if-false',
             [
              (anchor,
               head + '            if False:\n'
                     + '                class C:\n'
                     + '                    del a_cls\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d1b-dead-publish-finally',
             [
              (anchor,
               head + '            try:\n'
                     + '                class C:\n'
                     + '                    del a_cls\n'
                     + '            finally:\n'
                     + '                results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d2-builtins-lookuperror-rebind',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            import builtins\n'
                     + '            old = builtins.LookupError\n'
                     + '            builtins.LookupError = NameError\n'
                     + '            try:\n'
                     + '                box = {}\n'
                     + '                a_cls = box\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    except LookupError:\n'
                     + '                        pass\n'
                     + '                    a_cls["raw"] = log\n'
                     + '                results.append(module_box)\n'
                     + '            finally:\n'
                     + '                builtins.LookupError = old\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d3-prune-rebound-restore-source',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            a = box\n'
                     + '            p = box\n'
                     + '            a = {}\n'
                     + '            if True:\n'
                     + '                a = p\n'
                     + '            p = {}\n'
                     + '            box = {}\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(a)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d4-skipped-fresh-walrus',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     + '            sink = {}\n'
                     + '            cp,sink[((box:=box),0)[1]],sink[((False and (box:={"row":{}})),0)[1]],sink[((keep:=box),1)[1]],box=box.copy(),0,0,0,{"row":{}}\n'
                     + '            cp["row"]["raw"] = log\n'
                     + '            results.append(keep)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d5a-slice-shift-after-replace',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [{}, box]\n'
                     + '            ys = xs\n'
                     + '            xs[0] = {}\n'
                     + '            xs[:1] = []\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d5b-alias-reverse-after-replace',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [{}, box]\n'
                     + '            ys = xs\n'
                     + '            xs[0] = {}\n'
                     + '            ys.reverse()\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d6-same-statement-store-before-replace',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            xs[0]["raw"], xs[0] = log, {}\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d7-duplicate-indexed-targets',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box, {}]\n'
                     + '            xs[0], xs[0] = {}, box\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d7b-duplicate-indexed-targets-reversed',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box, {}]\n'
                     + '            xs[0], xs[0] = box, {}\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d8-nested-try-skipped-install',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    del a_cls\n'
                     + '                    try:\n'
                     + '                        a_cls = box\n'
                     + '                    except* NameError:\n'
                     + '                        pass\n'
                     + '                except NameError:\n'
                     + '                    pass\n'
                     + '                a_cls["raw"] = log\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('d9-for-iter-late-store',
             [
              (anchor,
               head + '            def clean(self):\n'
                     + '                return b"CLEAN"\n'
                     + '            def f():\n'
                     + '                w = Path.read_bytes\n'
                     + '                for ignored in ((rb := w), (w := clean)):\n'
                     + '                    pass\n'
                     + '                Path.r = rb\n'
                     + '                ignored = decode_body_log(log.r())\n'
                     + '                results.append(ignored)\n'
                     + '            f()\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_r36_shapes(self):
        # adjudication-r35 D-fixes, silent placements:
        # the inner-wrapped finally install (D8b),
        # non-string pair-key overwrite (D10),
        # binding-time mapping state (D11a/D11b) and
        # the double-delete unreachable publish
        # (D12).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        cases = [
            ('d8b-finally-install-inner-wrapped',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            a_cls = box\n'
                     + '            try:\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    finally:\n'
                     + '                        try:\n'
                     + '                            a_cls = box\n'
                     + '                        except NameError:\n'
                     + '                            pass\n'
                     + '                        a_cls["raw"] = log\n'
                     + '            except NameError:\n'
                     + '                pass\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
            ('d10-nonstring-pair-keys',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [dict([(0, box), (False, {})])]\n'
                     + '            xs[0][0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('d11a-obsolete-mapping-rebind',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            mapping = {"slot": {}}\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('d11b-obsolete-mapping-box-rebind',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            box = {}\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('d12-double-delete-unreachable',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    a_cls = box\n'
                     + '                    del a_cls\n'
                     + '                    del a_cls\n'
                     + '                finally:\n'
                     + '                    a_cls["raw"] = log\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
        ]
        for name, edits in cases:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_catches_r37_plants(self):
        # adjudication-r36 E-fixes, firing placements
        # (all fourteen findings are misses): the
        # for-target iterator read (E1), preserving
        # rebinds (E2/E2b), the memo horizon (E3),
        # ancestor exits and loop-else regions
        # (E4/E4b), the suppressing manager (E5), the
        # inherited metaclass (E6), the implicit
        # binding (E7), the builtins-alias setattr
        # (E8), the capture-window peer (E9), the
        # comprehension-result walrus (E10), the
        # walrus-wrapped slice (E11), the skipped
        # replacement (E12) and the unwind cleanup
        # and second raise (E13/E14).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        fire = [
            ('e1-for-target-iterator-effects',
             [
              (anchor,
               head + '            def clean(self):\n'
                     + '                return b"CLEAN"\n'
                     + '            def f():\n'
                     + '                w = clean\n'
                     + '                sink = {}\n'
                     + '                for sink[(rb := w)] in ((w := Path.read_bytes),):\n'
                     + '                    pass\n'
                     + '                Path.r = rb\n'
                     + '                ignored = decode_body_log(log.r())\n'
                     + '                results.append(ignored)\n'
                     + '            f()\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('e2-preserving-rebind-keeps-display',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            mapping = mapping\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e2b-preserving-copy-keeps-display',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            mapping = mapping.copy()\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e3-memo-binding-horizons',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": {}}\n'
                     + '            left = {"m": mapping}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            right = {"m": mapping}\n'
                     + '            *xs, = [left, right]\n'
                     + '            xs[1]["m"]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e4-ancestor-exit-skips-del',
             [
              (anchor,
               head + '            for _ in [0]:\n'
                     + '                break\n'
                     + '                class C:\n'
                     + '                    del absent\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e4b-loop-else-publish-empty-iter',
             [
              (anchor,
               head + '            for _ in []:\n'
                     + '                class C:\n'
                     + '                    del absent\n'
                     + '            else:\n'
                     + '                results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e5-suppress-keeps-publish-live',
             [
              (anchor,
               head + '            import contextlib\n'
                     + '            with contextlib.suppress(NameError):\n'
                     + '                class C:\n'
                     + '                    del absent\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e6-inherited-metaclass-prepare',
             [
              (anchor,
               head + '            class M(type):\n'
                     + '                @classmethod\n'
                     + '                def __prepare__(mcls, name, bases):\n'
                     + '                    return {"absent": 1}\n'
                     + '            class B(metaclass=M):\n'
                     + '                pass\n'
                     + '            class C(B):\n'
                     + '                del absent\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e7-implicit-class-binding',
             [
              (anchor,
               head + '            class C:\n'
                     + '                del __module__\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e8-setattr-builtins-alias',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            import builtins as b\n'
                     + '            old = b.LookupError\n'
                     + '            setattr(b, "LookupError", NameError)\n'
                     + '            try:\n'
                     + '                box = {}\n'
                     + '                a_cls = box\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    except LookupError:\n'
                     + '                        pass\n'
                     + '                    a_cls["raw"] = log\n'
                     + '                results.append(module_box)\n'
                     + '            finally:\n'
                     + '                setattr(b, "LookupError", old)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e9-capture-window-peer-source',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            p = box\n'
                     + '            *xs, = [box]\n'
                     + '            a = p\n'
                     + '            p = {}\n'
                     + '            box = {}\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(a)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e10-comprehension-result-walrus',
             [
              (anchor,
               head + '            box = {"row": {}}\n'
                     + '            sink = {}\n'
                     + '            cp,sink[((keep:=box),1)[1]],box=box.copy(),[(box:={"row":{}}) for _ in ()],{"row":{}}\n'
                     + '            cp["row"]["raw"] = log\n'
                     + '            results.append(keep)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e11-walrus-wrapped-slice-shift',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [{}, box]\n'
                     + '            xs[0] = {}\n'
                     + '            (ys := xs)[:1] = []\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e12-skipped-replacement-try-region',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            try:\n'
                     + '                raise ValueError\n'
                     + '                xs[0] = {}\n'
                     + '            except ValueError:\n'
                     + '                xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e13-unwind-handler-deletion',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            try:\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    finally:\n'
                     + '                        a_cls = box\n'
                     + '                        try:\n'
                     + '                            pass\n'
                     + '                        except NameError:\n'
                     + '                            pass\n'
                     + '                        else:\n'
                     + '                            del a_cls\n'
                     + '                        a_cls["raw"] = log\n'
                     + '            except NameError:\n'
                     + '                pass\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('e14-unwind-second-raise-skips-install',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            try:\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        try:\n'
                     + '                            del a_cls\n'
                     + '                        finally:\n'
                     + '                            del a_cls\n'
                     + '                            a_cls = box\n'
                     + '                    finally:\n'
                     + '                        a_cls["raw"] = log\n'
                     + '            except NameError:\n'
                     + '                pass\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
        ]
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_catches_r38_plants(self):
        # adjudication-r37 F-fixes: firing misses (F1,
        # F3, F4, F6, F7, F8, F11, F12, F14, F15, F18,
        # F19, plus F10a on 3.14+ / F10b below) and
        # silenced precision (F2, F5/F5b, F9, F13,
        # F16, F17, plus the off-interpreter F10
        # counterpart): iterator/target order, the
        # in-statement seed, the comprehension
        # walrus, the live-alias copy, unpack and
        # item overrides, the compound exit, the
        # suppressed class replay, current base
        # identity, the diamond, version implicits,
        # the builtins chain, peer direction, the
        # index load, sibling handlers, the
        # suppressed replacement, the match case,
        # the quiet handler, the outward catcher
        # and the foreign raise.
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        mod = "def execute("
        clean = ('            def clean(self):\n'
                 + '                return b"CLEAN"\n')
        fire = [
            ('f1-iterator-vs-target-order',
             [
              (anchor,
               head + clean
                     + '            def f():\n'
                     + '                w = clean\n'
                     + '                sink = {}\n'
                     + '                for sink[((w := Path.read_bytes), '
                     + '(rb := w))] in ((w := clean),):\n'
                     + '                    pass\n'
                     + '                Path.r = rb\n'
                     + '                ignored = decode_body_log(log.r())\n'
                     + '                results.append(ignored)\n'
                     + '            f()\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('f3-comprehension-walrus-env',
             [
              (anchor,
               head + clean
                     + '            def f():\n'
                     + '                w = clean\n'
                     + '                ignored = [(rb := w) for w in '
                     + '(Path.read_bytes,)]\n'
                     + '                Path.r = rb\n'
                     + '                ignored = decode_body_log(log.r())\n'
                     + '                results.append(ignored)\n'
                     + '            f()\n'
               + use),
             ],
             'tainted path escapes to log.r()'),
            ('f4-copy-through-live-alias',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            alias = mapping\n'
                     + '            mapping = alias.copy()\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f6-exit-in-preceding-compound',
             [
              (anchor,
               head + '            for _ in [0]:\n'
                     + '                if True:\n'
                     + '                    break\n'
                     + '                class C:\n'
                     + '                    del absent\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f7-suppress-class-replay',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            import contextlib\n'
                     + '            class C:\n'
                     + '                with contextlib.suppress(NameError):\n'
                     + '                    del a_cls\n'
                     + '                a_cls["raw"] = log\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f8-historical-base-identity',
             [
              (anchor,
               head + '            class M(type):\n'
                     + '                @classmethod\n'
                     + '                def __prepare__(mcls, name, bases):\n'
                     + '                    return {"absent": 1}\n'
                     + '            class Custom(metaclass=M):\n'
                     + '                pass\n'
                     + '            class B:\n'
                     + '                pass\n'
                     + '            B = Custom\n'
                     + '            class C(B):\n'
                     + '                del absent\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f11-builtins-alias-chain',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            import builtins as b\n'
                     + '            alias = b\n'
                     + '            old = alias.LookupError\n'
                     + '            setattr(alias, "LookupError", NameError)\n'
                     + '            try:\n'
                     + '                box = {}\n'
                     + '                a_cls = box\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    except LookupError:\n'
                     + '                        pass\n'
                     + '                    a_cls["raw"] = log\n'
                     + '                results.append(module_box)\n'
                     + '            finally:\n'
                     + '                setattr(alias, "LookupError", old)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f12-peer-direction',
             [
              (anchor,
               head + '            p = {}\n'
                     + '            box = p\n'
                     + '            *xs, = [box]\n'
                     + '            a = p\n'
                     + '            p = {}\n'
                     + '            box = {}\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(a)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f14-sibling-handlers',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            try:\n'
                     + '                raise TypeError\n'
                     + '            except ValueError:\n'
                     + '                xs[0] = {}\n'
                     + '            except TypeError:\n'
                     + '                xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f15-suppress-skipped-replacement',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            import contextlib\n'
                     + '            with contextlib.suppress(ZeroDivisionError):\n'
                     + '                1 / 0\n'
                     + '                xs[0] = {}\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f18-outward-catcher-finally',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            class C:\n'
                     + '                try:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    finally:\n'
                     + '                        del a_cls\n'
                     + '                        a_cls = box\n'
                     + '                except NameError:\n'
                     + '                    pass\n'
                     + '                a_cls["raw"] = log\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
            ('f19-other-name-raise',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            try:\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        try:\n'
                     + '                            del a_cls\n'
                     + '                        finally:\n'
                     + '                            del another_absent\n'
                     + '                            a_cls = box\n'
                     + '                    finally:\n'
                     + '                        a_cls["raw"] = log\n'
                     + '            except NameError:\n'
                     + '                pass\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             'tainted path escapes to results.append()'),
        ]
        silent = [
            ('f2-instatement-later-seed',
             [
              (anchor,
               head + clean
                     + '            def f():\n'
                     + '                w = clean\n'
                     + '                for ignored in ((rb := w), '
                     + '(w := Path.read_bytes),\n'
                     + '                                setattr(Path, "r", rb)):\n'
                     + '                    pass\n'
                     + '                Path.r = rb\n'
                     + '                ignored = decode_body_log(log.r())\n'
                     + '                results.append(ignored)\n'
                     + '            f()\n'
               + use),
             ],
             ),
            ('f5-unpack-override-retained',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            mapping = {**mapping, "slot": {}}\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('f5b-copy-then-item-replace',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            mapping = {"slot": box}\n'
                     + '            mapping = mapping.copy()\n'
                     + '            mapping["slot"] = {}\n'
                     + '            *xs, = [dict(mapping.copy(), extra={})]\n'
                     + '            xs[0]["slot"]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('f9-diamond-false-cycle',
             [
              (anchor,
               head + '            class B: pass\n'
                     + '            class Left(B): pass\n'
                     + '            class Right(B): pass\n'
                     + '            class C(Left, Right):\n'
                     + '                del absent\n'
                     + '            results.append({"raw": log})\n'
               + use),
             ],
             ),
            ('f13-augassign-index-load',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            xs[0] = {}\n'
                     + '            other = [[]]\n'
                     + '            other[0 if xs else 0] += []\n'
                     + '            xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('f16-match-case-coexec',
             [
              (anchor,
               head + '            box = {}\n'
                     + '            *xs, = [box]\n'
                     + '            match True:\n'
                     + '                case True:\n'
                     + '                    xs[0] = {}\n'
                     + '                    xs[0]["raw"] = log\n'
                     + '            results.append(box)\n'
               + use),
             ],
             ),
            ('f17-unreachable-handler-del',
             [
              (mod,
               'module_box = {}\n'
               'a_cls = module_box\n'
               + mod),
              (anchor,
               head + '            box = {}\n'
                     + '            try:\n'
                     + '                class C:\n'
                     + '                    try:\n'
                     + '                        del a_cls\n'
                     + '                    finally:\n'
                     + '                        a_cls = box\n'
                     + '                        try:\n'
                     + '                            pass\n'
                     + '                        except NameError:\n'
                     + '                            del a_cls\n'
                     + '                        a_cls["raw"] = log\n'
                     + '            except NameError:\n'
                     + '                pass\n'
                     + '            results.append(module_box)\n'
               + use),
             ],
             ),
        ]
        f10a = ('f10a-firstlineno',
                [
                 (anchor,
                  head + '            class C:\n'
                        + '                del __firstlineno__\n'
                        + '            results.append({"raw": log})\n'
                  + use),
                ],
                'tainted path escapes to results.append()')
        f10b = ('f10b-annotations',
                [
                 (anchor,
                  head + '            class C:\n'
                        + '                x: int\n'
                        + '                del __annotations__\n'
                        + '            results.append({"raw": log})\n'
                  + use),
                ],
                'tainted path escapes to results.append()')
        if sys.version_info >= (3, 14):
            fire.append(f10a)
            silent.append((f10b[0], f10b[1]))
        else:
            silent.append((f10a[0], f10a[1]))
            fire.append(f10b)
        for name, edits, fragment in fire:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                violations = _binding_violations(planted)
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")
        for name, edits in silent:
            with self.subTest(shape=name):
                planted = source
                for find, repl in edits:
                    self.assertEqual(planted.count(find), 1, name)
                    planted = planted.replace(find, repl)
                self.assertEqual(
                    _binding_violations(planted), [], name)

    def test_tripwire_readcap_scope_isolation(self):
        # readcap provenance is per-scope: a sibling
        # scope's capability never leaks in, a local
        # clean rebind shadows a module one — but a
        # module capability used but never rebound
        # locally still fires (fallback, not leak).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        module_anchor = "def execute("
        prepare_anchor = "    before = source_identity(root)\n"
        self.assertEqual(source.count(anchor), 1)
        self.assertEqual(source.count(module_anchor), 1)
        self.assertEqual(source.count(prepare_anchor), 1)
        sibling = source.replace(
            prepare_anchor,
            "    rb = Path.read_bytes\n" + prepare_anchor)
        sibling = sibling.replace(
            anchor,
            head + "            Path.r = rb\n"
            "            output = decode_body_log(log.r())\n"
            + use)
        with self.subTest(shape="sibling-capability-silent"):
            self.assertEqual(_binding_violations(sibling), [])
        shadowed = source.replace(
            module_anchor,
            "rb = Path.read_bytes\n" + module_anchor)
        shadowed = shadowed.replace(
            anchor,
            head + "            def clean(self):\n"
            "                return \"harmless\"\n"
            "            rb = clean\n"
            "            Path.r = rb\n"
            "            output = decode_body_log(log.r())\n"
            + use)
        with self.subTest(shape="module-capability-shadowed"):
            self.assertEqual(_binding_violations(shadowed), [])
        fallback = source.replace(
            module_anchor,
            "rb = Path.read_bytes\n" + module_anchor)
        fallback = fallback.replace(
            anchor,
            head + "            Path.r = rb\n"
            "            output = decode_body_log(log.r())\n"
            + use)
        with self.subTest(shape="module-capability-fallback"):
            violations = _binding_violations(fallback)
            self.assertTrue(
                any("tainted path escapes to log.r()"
                    in violation for violation in violations),
                violations)

    def test_tripwire_dict_builtin_identity(self):
        # unbound-dict trust dies with the builtin: a
        # top-level class/cdef named dict shadows it,
        # so dict.update(ns, ...) calls fail dynamic
        # (a top-level sink/consumer def keeps its
        # wholesale-replacement exemption instead).
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        module_anchor = "def execute("
        self.assertEqual(source.count(anchor), 1)
        self.assertEqual(source.count(module_anchor), 1)
        evil = source.replace(
            module_anchor,
            "class dict:\n"
            "    @staticmethod\n"
            "    def update(ns, **kwargs):\n"
            "        ns[\"_say\"] = open\n" + module_anchor)
        evil = evil.replace(
            anchor,
            head + "            dict.update(globals(), clean=1)\n"
            "            _say(log)\n" + use)
        with self.subTest(shape="top-level-class-dict"):
            violations = _binding_violations(evil)
            self.assertTrue(
                any("dynamic namespace rebind" in violation
                    for violation in violations),
                violations)


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
            verdict = None
            if run_hook is not None:
                # the hook decides the command outcome
                # FIRST: a raise, or a verdict with a
                # failing returncode, means the unmount
                # never happened — its postconditions
                # apply only to a successful unmount (a
                # failed one retains its contents).
                verdict = run_hook(cmd)
            if cmd[:1] == ["umount"]:
                failed = verdict is not None \
                    and verdict.returncode != 0
                if not failed:
                    # emulate the postcondition real
                    # unmount provides: the mountpoint
                    # survives, its contents are gone.
                    # Precondition (asserted): only the
                    # tmpfs runtime may be nonempty — its
                    # contents lived on the mount. A real
                    # bind-unmount would REVEAL underlying
                    # contents instead of deleting them,
                    # so a nonempty bind target fails the
                    # fixture.
                    target = Path(cmd[1])
                    if target.is_relative_to(root) \
                            and target.is_dir() \
                            and not target.is_symlink():
                        # In passthrough mode mounts bypass
                        # this mock (the test's Popen mock
                        # owns them), so tmpfs runtimes —
                        # always direct children of rt/ —
                        # are recognized by position.
                        # Anywhere else a bypassing mount
                        # is a harness bug and must fail.
                        known_tmpfs = str(target) in tmpfs_targets \
                            or (passthrough_run_cancel
                                and target.parent == runtime_base)
                        if any(target.iterdir()) \
                                and not known_tmpfs:
                            raise AssertionError(
                                "unmount emulation fed "
                                f"nonempty bind target: {target}")
                        for child in target.iterdir():
                            if child.is_dir() \
                                    and not child.is_symlink():
                                shutil.rmtree(child)
                            else:
                                child.unlink()
            if verdict is not None:
                if kwargs.get("check") \
                        and verdict.returncode != 0:
                    # checked-exit fidelity: mirror what
                    # subprocess.run and the real
                    # _run_cancel do under check=True —
                    # a nonzero verdict raises instead of
                    # following the success path.
                    raise subprocess.CalledProcessError(
                        verdict.returncode, cmd)
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
            # failed unmounts retain their contents —
            # the mock must not delete ahead of the
            # command outcome (a spawn failure raises
            # before any postcondition runs).
            tmpfs_targets = [
                cmd[-1] for cmd in calls
                if cmd[:2] == ["mount", "-t"]]
            self.assertEqual(len(tmpfs_targets), 1)
            self.assertTrue(
                any(Path(tmpfs_targets[0]).iterdir()))
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

    def test_bind_mount_failure_raises_and_registers_nothing(self):
        # checked-exit fidelity: a nonzero bind mount
        # raises CalledProcessError (like the real
        # _run_cancel under check=True) instead of
        # following the success path — the remount
        # never runs and the failed target is never
        # registered for cleanup.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def fail_bind(cmd):
                if cmd[:2] == ["mount", "--bind"]:
                    return mock.Mock(returncode=32,
                                     stderr="mount failed")
                return None
            outcome, error, calls, printed = self._drive(
                root, out, lock,
                run_logged=lambda *a, **k: (0, False, b""),
                run_hook=fail_bind)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error,
                                  subprocess.CalledProcessError)
            self.assertEqual(error.returncode, 32)
            binds = [cmd for cmd in calls
                     if cmd[:2] == ["mount", "--bind"]]
            self.assertEqual(len(binds), 1)
            self.assertFalse(any(cmd[:2] == ["mount", "-o"]
                                 for cmd in calls))
            self.assertNotIn(binds[0][-1],
                             self._umount_targets(calls))
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
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

    def test_manifest_reader_refuses_fifo_without_hang(self):
        # a FIFO at the manifest name refuses fast
        # (ValueError): the privileged read must never
        # block on a writerless FIFO. The watchdog
        # rescues a hanging worker with a writer end,
        # then fails: a rescue always means the shape
        # regressed.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            os.mkfifo(path)
            errors, opened = [], []
            before = set(os.listdir("/proc/self/fd"))

            def attempt():
                try:
                    opened.append(
                        lane._read_bounded_bytes(path))
                except BaseException as error:
                    errors.append(error)

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
                rescued, "manifest read blocked on a writerless FIFO")
            self.assertEqual(opened, [])
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_manifest_reader_refuses_symlink_and_directory(self):
        # a swapped-in symlink is never followed
        # (ELOOP from the open itself); a directory is
        # not a regular file (ValueError from the pin).
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "real.json"
            target.write_bytes(b"{}")
            link = Path(tmp) / "manifest.json"
            link.symlink_to(target)
            with self.assertRaises(OSError) as caught:
                lane._read_bounded_bytes(link)
            self.assertEqual(caught.exception.errno, errno.ELOOP)
            with self.assertRaises(ValueError):
                lane._read_bounded_bytes(Path(tmp))
            self.assertEqual(
                lane._read_bounded_bytes(target), b"{}")

    def test_manifest_reader_bounds_oversized_body(self):
        # a streaming writer cannot gorge root: past
        # 1 MiB the read fails closed (ValueError).
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_bytes(b"x" * (lane._BOUNDED_READ_MAX + 1))
            before = set(os.listdir("/proc/self/fd"))
            with self.assertRaises(ValueError) as caught:
                lane._read_bounded_bytes(path)
            self.assertIn("exceeds", str(caught.exception))
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_manifest_reader_roundtrips_regular_file(self):
        # a regular manifest reads byte-identical; a
        # missing one still raises FileNotFoundError.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_bytes(b'{"schema": 1}')
            self.assertEqual(lane._read_bounded_bytes(path),
                             b'{"schema": 1}')
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                lane._read_bounded_bytes(path)

    def test_execute_fifo_manifest_refuses_fast(self):
        # the privileged manifest read goes through the
        # bounded reader: a planted FIFO fails the drive
        # closed (ValueError) instead of hanging root.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            (out / "manifest.json").unlink()
            os.mkfifo(out / "manifest.json")
            outcomes = []

            def attempt():
                outcomes.append(self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b"")))

            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(10)
            rescued = worker.is_alive()
            if rescued:
                with contextlib.suppress(OSError):
                    release = os.open(
                        out / "manifest.json",
                        os.O_WRONLY | os.O_NONBLOCK)
                    os.close(release)
                worker.join(10)
            self.assertFalse(
                rescued, "execute blocked on a FIFO manifest")
            self.assertEqual(len(outcomes), 1)
            outcome, error, calls, printed = outcomes[0]
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("prepared manifest is not a regular file: ", str(error))

    def test_main_run_prepared_fifo_manifest_refuses_fast(self):
        # the --run-prepared manifest read goes through
        # the bounded reader: a planted FIFO fails main
        # closed (ValueError) instead of hanging it.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            fifo = out / "manifest.json"
            os.mkfifo(fifo)
            errors = []

            def attempt():
                try:
                    lane.main(_root=Path(tmp))
                except BaseException as error:
                    errors.append(error)

            argv = ["sudo_lane.py", "--run-prepared", str(out)]
            with mock.patch.object(sys, "argv", argv):
                worker = threading.Thread(target=attempt,
                                          daemon=True)
                worker.start()
                worker.join(10)
                rescued = worker.is_alive()
                if rescued:
                    with contextlib.suppress(OSError):
                        release = os.open(
                            fifo, os.O_WRONLY | os.O_NONBLOCK)
                        os.close(release)
                    worker.join(10)
            self.assertFalse(
                rescued, "main blocked on a FIFO manifest")
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertIn(
                "prepared manifest is not a regular file: ", str(errors[0]))

    def test_main_manifest_reread_fifo_refuses_fast(self):
        # the pre-launch manifest re-read (after a
        # mocked prepare) refuses a FIFO the same way.
        # main creates --out itself, so the mocked
        # prepare plants the FIFO (a preparer that left
        # one behind).
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            manifest = {"sha256": {"stage/runner.py": "00" * 32}}

            def fake_prepare(*args, **kwargs):
                os.mkfifo(out / "manifest.json")
                return manifest

            errors = []

            def attempt():
                try:
                    lane.main(_root=Path(tmp))
                except BaseException as error:
                    errors.append(error)

            argv = ["sudo_lane.py", "--out", str(out)]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(lane, "prepare",
                                      side_effect=fake_prepare), \
                    mock.patch.object(fcntl, "flock"):
                worker = threading.Thread(target=attempt,
                                          daemon=True)
                worker.start()
                worker.join(10)
                rescued = worker.is_alive()
                if rescued:
                    with contextlib.suppress(OSError):
                        release = os.open(
                            out / "manifest.json",
                            os.O_WRONLY | os.O_NONBLOCK)
                        os.close(release)
                    worker.join(10)
            self.assertFalse(
                rescued, "main blocked on a FIFO re-read")
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertIn(
                "prepared manifest is not a regular file: ", str(errors[0]))

    def test_main_runner_fifo_refuses_fast(self):
        # the stage-runner freeze read (root when main
        # itself runs as root) refuses a FIFO runner.
        # The mocked prepare stages a consistent
        # manifest plus the FIFO runner.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            manifest = {"sha256": {"stage/runner.py": "ab" * 32}}

            def fake_prepare(*args, **kwargs):
                (out / "manifest.json").write_text(
                    json.dumps(manifest))
                (out / "stage").mkdir()
                os.mkfifo(out / "stage/runner.py")
                return manifest

            errors = []

            def attempt():
                try:
                    lane.main(_root=Path(tmp))
                except BaseException as error:
                    errors.append(error)

            argv = ["sudo_lane.py", "--out", str(out)]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(lane, "prepare",
                                      side_effect=fake_prepare), \
                    mock.patch.object(fcntl, "flock"):
                worker = threading.Thread(target=attempt,
                                          daemon=True)
                worker.start()
                worker.join(10)
                rescued = worker.is_alive()
                if rescued:
                    with contextlib.suppress(OSError):
                        release = os.open(
                            out / "stage/runner.py",
                            os.O_WRONLY | os.O_NONBLOCK)
                        os.close(release)
                    worker.join(10)
            self.assertFalse(
                rescued, "main blocked on a FIFO runner")
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertIn(
                "prepared runner is not a regular file: ", str(errors[0]))

    def test_bounded_reader_exact_cap_reads_ok(self):
        # the cap is strict greater-than: exactly 1 MiB
        # reads fully (pins > against >=).
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_bytes(b"y" * lane._BOUNDED_READ_MAX)
            self.assertEqual(lane._read_bounded_bytes(path),
                             b"y" * lane._BOUNDED_READ_MAX)

    def test_open_pinned_memory_error_releases_both_fds(self):
        # a MemoryError between acquiring the child and
        # handing it over (the ENOTDIR message build)
        # releases both descriptors: OSError-only arms
        # would strand them.
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b"
            deep.mkdir(parents=True)
            real_fstat = os.fstat
            calls = []

            def flaky_fstat(fd):
                calls.append(fd)
                result = real_fstat(fd)
                if len(calls) == 2:
                    raise MemoryError("message build")
                return result

            before = set(os.listdir("/proc/self/fd"))
            with mock.patch.object(os, "fstat",
                                   side_effect=flaky_fstat):
                with self.assertRaises(MemoryError):
                    lane._open_pinned(deep)
            self.assertTrue(calls)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_open_pinned_parent_close_memory_error_releases_child(
            self):
        # a MemoryError from the parent close still
        # releases the owned child through the widened
        # outer arm (the parent number itself was
        # closed before the error surfaced).
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b"
            deep.mkdir(parents=True)
            real_close = os.close
            state = {"fail": True}

            def flaky_close(fd):
                real_close(fd)
                if state["fail"]:
                    state["fail"] = False
                    raise MemoryError("close path")

            before = set(os.listdir("/proc/self/fd"))
            with mock.patch.object(os, "close",
                                   side_effect=flaky_close):
                with self.assertRaises(MemoryError):
                    lane._open_pinned(deep)
            self.assertFalse(state["fail"])
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_open_pinned_parent_fail_closes_owned_once(self):
        # take-and-clear in the parent-failure arm: the
        # parent close fails (OSError), then the owned
        # close raises MemoryError — owned is attempted
        # exactly once (clearing before the close), so
        # the outer arm cannot close the number again.
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b"
            deep.mkdir(parents=True)
            real_close = os.close
            closed, state = [], {"step": 0}

            def flaky_close(fd):
                closed.append(fd)
                real_close(fd)
                state["step"] += 1
                if state["step"] == 1:
                    raise OSError(errno.EIO, "parent lost")
                if state["step"] == 2:
                    raise MemoryError("owned close path")

            before = set(os.listdir("/proc/self/fd"))
            with mock.patch.object(os, "close",
                                   side_effect=flaky_close):
                with self.assertRaises(MemoryError):
                    lane._open_pinned(deep)
            self.assertEqual(len(closed), 2)
            self.assertEqual(len(set(closed)), 2)
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
                    with self.assertRaises(OSError) as raised:
                        with lane.cancellation():
                            pass
                    self.assertEqual(raised.exception.errno,
                                     errno.EIO)
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
            # A worker that survived both joins may still
            # dup2 onto these numbers: closing them here
            # could hand a reused number to that dup2, so
            # the already-failed path leaks rather than
            # corrupts (the join assertion above fired).
            if worker is None or not worker.is_alive():
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

    def test_cancellation_ambient_value_error_does_not_mask_reap(
            self):
        # an exception the CALLER is handling is not this
        # body's error: a clean body inside `except
        # ValueError` plus an outer custody failure still
        # raises the OSError — sys.exception() would have
        # seen the ambient ValueError and suppressed it.
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        lane._CANCEL_REQUESTED = False
        lane._CANCELLATION_REPAIR = None
        try:
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(errno.EIO, "Input/output "
                                                   "error")):
                try:
                    raise ValueError("already handled")
                except ValueError:
                    with self.assertRaises(OSError) as raised:
                        with lane.cancellation():
                            pass
            self.assertEqual(raised.exception.errno, errno.EIO)
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot
            lane._CANCELLATION_REAP_FAILED = saved_reap

    def test_cancellation_ambient_keyboard_interrupt_does_not_mask(
            self):
        # same masking through a handled
        # KeyboardInterrupt: the ambient interrupt is not
        # a body error the custody failure defers to.
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        lane._CANCEL_REQUESTED = False
        lane._CANCELLATION_REPAIR = None
        try:
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(errno.EIO, "Input/output "
                                                   "error")):
                try:
                    raise KeyboardInterrupt()
                except KeyboardInterrupt:
                    with self.assertRaises(OSError) as raised:
                        with lane.cancellation():
                            pass
            self.assertEqual(raised.exception.errno, errno.EIO)
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot
            lane._CANCELLATION_REAP_FAILED = saved_reap

    def test_cancellation_interrupted_body_still_fails_on_reap(
            self):
        # the gate's InterruptedError arm is live:
        # a cancel landing during digest raises it from
        # the body, so a body InterruptedError plus an
        # outer custody failure must propagate the
        # OSError, like SystemExit.
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        calls = []
        lane._CANCEL_REQUESTED = False
        lane._CANCELLATION_REPAIR = lambda: calls.append(1)
        try:
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(errno.EIO, "Input/output "
                                                   "error")):
                with self.assertRaises(OSError) as raised:
                    with lane.cancellation():
                        raise InterruptedError("body")
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
                    with self.assertRaises(OSError) as raised:
                        with lane.cancellation():
                            pass
                    self.assertEqual(raised.exception.errno,
                                     errno.EIO)
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
