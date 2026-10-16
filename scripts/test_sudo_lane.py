#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial runner checks; no privilege or kernel support required."""
import ast
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
        yield
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
            with mock.patch.object(lane, "_text_sink",
                                   side_effect=OSError("nope")):
                with self.assertRaises(OSError):
                    lane.dump(out / "b.json", {})
            self.assertEqual(fds(), before)


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


class CapturedBytesBinding(unittest.TestCase):
    READ_ATTRS = ("open", "read_text", "read_bytes", "read")
    PATH_CONSUMERS = ("run_logged",)

    def test_verdict_sites_never_reopen_log_paths(self):
        # the substitution fix is structural: verdicts hash and
        # parse fd-captured bytes. A call site reverted to path
        # reads stays green functionally, so pin the shape with a
        # narrow tripwire (taint over execute/prepare): no reads
        # through the log path or its aliases, no other consumer
        # of the path, every run_logged 3-unpacked with the bytes
        # used, and the deleted reader gone module-wide. The
        # mock-driven ExecuteWiring scenarios prove the behavior;
        # this guard only catches mechanical reverts.
        tree = ast.parse(Path(lane.__file__).read_text())
        funcs = [node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef)
                 and node.name in ("execute", "prepare")]
        self.assertEqual(len(funcs), 2)
        violations = []
        for func in funcs:
            tainted = {"log"}
            changed = True
            while changed:
                changed = False
                for node in ast.walk(func):
                    if isinstance(node, ast.Assign) \
                            and isinstance(node.value, ast.Name) \
                            and node.value.id in tainted:
                        for target in node.targets:
                            if isinstance(target, ast.Name) \
                                    and target.id not in tainted:
                                tainted.add(target.id)
                                changed = True
            used = {node.id for node in ast.walk(func)
                    if isinstance(node, ast.Name)
                    and isinstance(node.ctx, ast.Load)}
            run_logged_calls = 0
            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func
                if isinstance(called, ast.Attribute) \
                        and called.attr in self.READ_ATTRS \
                        and isinstance(called.value, ast.Name) \
                        and called.value.id in tainted:
                    violations.append(
                        f"{func.name}:{node.lineno} reads tainted path")
                if isinstance(called, ast.Name) \
                        and called.id not in self.PATH_CONSUMERS \
                        and any(isinstance(arg, ast.Name)
                                and arg.id in tainted for arg in node.args):
                    violations.append(
                        f"{func.name}:{node.lineno} tainted path escapes "
                        f"to {called.id}()")
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
                    elif isinstance(elts[2], ast.Name) \
                            and elts[2].id not in used:
                        violations.append(
                            f"{func.name}:{node.lineno} captured "
                            "bytes unused")
            self.assertGreater(run_logged_calls, 0, func.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Name) \
                    and node.func.id == "read_body_log":
                violations.append(f"deleted reader at line {node.lineno}")
        self.assertEqual(violations, [])


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


class ExecuteWiring(unittest.TestCase):
    """Mock-driven execute() scenarios: finally wiring, publish
    precedence, signal shielding, and captured-bytes binding.

    Mocks replace only the privilege boundary (euid, mounts,
    stage verification, inventory reconciliation, child runs);
    the execute/finally control flow, verdicts, and publishing
    under test are real.
    """

    def _prepared_out(self, root):
        out = root / "out"
        (out / "stage").mkdir(parents=True)
        (out / "logs").mkdir()
        manifest = {"schema": "kryprobe-privileged-lane/v1", "artifacts": [],
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
               dump_hook=None):
        saved_flag = lane._CANCEL_REQUESTED
        calls = []
        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:1] == ["umount"]:
                # emulate the postcondition real unmount provides:
                # the mountpoint survives, its contents are gone.
                target = Path(cmd[1])
                if target.is_relative_to(root) and target.is_dir() \
                        and not target.is_symlink():
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
        patches = [
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(lane, "verify_stage"),
            mock.patch.object(lane, "reconcile"),
            mock.patch.object(lane.subprocess, "run", side_effect=fake_run),
            mock.patch("tempfile.mkdtemp", side_effect=fake_mkdtemp),
            mock.patch.object(lane, "run_logged", side_effect=run_logged),
        ]
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
            outcome, error, calls, printed = self._drive(
                root, out, lock, run_logged=boom, dump_hook=nospace)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, FileNotFoundError)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self.assertGreater(len(self._umount_targets(calls)), 0)
            self.assertIn("failure summary not published", printed)
            self.assertIn("evidence publishing problems", printed)
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
            self.assertTrue((out / "ownership.json").is_file())
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


class ProcessCustody(unittest.TestCase):
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
