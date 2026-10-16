#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial runner checks; no privilege or kernel support required."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys
import copy
import ctypes
import fcntl
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
                     printed_missing, marker="reconcile: partial\n"):
    return (
        f"selftest bpf: partial ({printed_missing} missing; ring={ring} drop={drop}"
        f" trunc={trunc} queue={queue})\n"
        f"selftest bpf: entries={entries} returns={returns} received={received}"
        f" ring={ring} drop={drop} trunc={trunc} queue={queue}\n"
        + marker
    )


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
            _partial_output(9, 9, 18, 1, 1, 0, 0, 2), 10)
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
        self.assertIsNone(lane.partial_receipt(
            _partial_output(101, 99, 200, 0, 0, 0, 0, 0), 100))

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
        base = _partial_output(9, 9, 18, 1, 1, 0, 0, 2)
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
        entries = "selftest bpf: entries=9 returns=9 received=18 ring=1 drop=1 trunc=0 queue=0\n"
        partial = "selftest bpf: partial (2 missing; ring=1 drop=1 trunc=0 queue=0)\n"
        marker = "reconcile: partial\n"
        bad = [
            partial + entries + marker + entries,  # duplicated entries line
            partial + partial + entries + marker,  # duplicated partial line
            entries + marker,  # partial line missing
            partial + marker,  # entries line missing
            partial + entries + marker + "reconcile: partial \n",  # trailing space
        ]
        for output in bad:
            with self.subTest(output=output):
                self.assertIsNone(lane.partial_receipt(output, 10))

    def test_unicode_digits_rejected(self):
        output = _partial_output(9, 9, 18, 1, 1, 0, 0, 2)
        output = output.replace("entries=9", "entries=\uff19")
        self.assertIsNone(lane.partial_receipt(output, 10))


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
            (3, _partial_output(9, 9, 18, 1, 1, 0, 0, 2,
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


class ProcessCustody(unittest.TestCase):
    def test_timeout_kills_and_reaps_owned_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            late = Path(tmp) / "late"
            code, timed_out = lane.run_logged(
                ["sh", "-c", 'sleep 2; touch "$1"', "fixture", str(late)],
                Path(tmp) / "timeout.log", timeout=0.05,
            )
            self.assertTrue(timed_out)
            self.assertEqual(code, 124)
            self.assertFalse(late.exists())

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
                code, timed_out = lane.run_logged(
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
