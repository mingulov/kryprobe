#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host tests for per-kind cell receipt builders (attempt 4, RED-first).

``cells.build_cell`` turns one boot's serial console into the sealed
cell receipt + ledgers. Each test feeds a fixture console (built
programmatically, never a live guest) and pins the fail-closed
behavior: exact op counts, gapless sequences, ordered marks, and
honest UNSUPPORTED outcomes where prerequisites are absent.
"""

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from kcrypto_qemu_demo import cells  # noqa: E402

PROC = {"exit": 0, "timed_out": False, "reaped": True}


def mark(name, ts):
    return f'DEMO:MARK {{"name": "{name}", "ts_mono": {ts}}}'


def ledger(seq, alloc, status=0, ts=10.0, name="cbc(aes)"):
    return (
        f'DEMO:LEDGER {{"seq": {seq}, "op": "encrypt", "bytes": 4096,'
        f' "status": {status}, "alloc_id": "{alloc}", "name": "{name}",'
        f' "ts_mono": {ts}}}'
    )


def registry(name, driver, priority, rtype="skcipher"):
    return (
        f'DEMO:REGISTRY {{"name": "{name}", "driver": "{driver}",'
        f' "priority": {priority}, "type": "{rtype}"}}'
    )


def krepo(calls, op_bytes=4096, errors=0, verdict="observed",
          missing=()):
    obs = (
        '{"operation_class": "encrypt", "phase": "returned",'
        ' "backend_payload": {"row": "agg", "counts": {"calls": %d,'
        ' "errors": %d, "ok": %d}, "bytes": %d}}'
        % (calls, errors, calls, calls * op_bytes)
    )
    return (
        "DEMO:KRYPROBE-BEGIN\n"
        '{"observations": [%s], "verdict": {"status": "%s",'
        ' "missing": [%s]}}\n'
        "DEMO:KRYPROBE-END\n"
        % (obs, verdict, ", ".join('"%s"' % m for m in missing))
    )


KREPO = krepo(4)


def krepo_drivers(specs, verdict="observed", missing=()):
    """KRYPROBE block with per-driver encrypt rows.

    Each spec is (driver, calls, ok, queued): async backends
    (virtio-crypto) report queued-not-returned counts, so the
    queued split is first-class here.
    """
    obs = []
    for driver, calls, ok, queued in specs:
        obs.append(
            '{"operation_class": "encrypt", "phase": "returned",'
            ' "backend_payload": {"row": "agg", "driver": "%s",'
            ' "counts": {"calls": %d, "errors": 0, "ok": %d,'
            ' "queued": %d}, "bytes": %d}}'
            % (driver, calls, ok, queued, calls * 4096)
        )
    return (
        "DEMO:KRYPROBE-BEGIN\n"
        '{"observations": [%s], "verdict": {"status": "%s",'
        ' "missing": [%s]}}\n'
        "DEMO:KRYPROBE-END\n"
        % (", ".join(obs), verdict,
           ", ".join('"%s"' % m for m in missing))
    )


KRYPROBE_EXIT = 'DEMO:PROBE {"fact": "kryprobe-exit", "exit": 0}'

PRELUDE_MARKS = [
    mark("INIT-READY", 1.0),
    mark("MANIFEST-OK", 1.5),
    mark("PRELUDE-DONE", 2.0),
]


def cell(workload, cell_id="D01"):
    return {
        "id": cell_id,
        "title": "fixture",
        "image": "img-7014-base",
        "workload": workload,
        "limits": {"timeout_s": 180},
        "expected_evidence": ["cell-%s.json" % cell_id],
    }


class D01Tests(unittest.TestCase):
    def _console(self, n_each=2):
        lines = list(PRELUDE_MARKS)
        lines += [
            registry("cbc(aes)", "cbc-aes-aesni", 400),
            registry("cbc(aes)", "cbc-aes-generic", 100),
            'DEMO:PROBE {"fact": "selected", "name": "cbc(aes)",'
            ' "driver": "cbc-aes-aesni"}',
            mark("KRYPROBE-START", 2.5),
            mark("WORKLOAD-START", 3.0),
        ]
        ts = 4.0
        for seq in range(n_each):
            lines.append(ledger(seq, "d01-generic", ts=round(ts, 1)))
            ts += 0.1
        for seq in range(n_each):
            lines.append(ledger(seq, "d01-driver", ts=round(ts, 1)))
            ts += 0.1
        lines += [mark("WORKLOAD-STOP", ts), mark("WORKLOAD-DONE", ts + 1)]
        lines.append(KRYPROBE_EXIT)
        return "[ 0.1] noise\n" + "\n".join(lines) + "\n" + KREPO

    def _workload(self, n_each=2):
        return {"kind": "provider-selection", "requests": 2 * n_each,
                "block_bytes": 4096, "rate_per_s": 10}

    def test_d01_receipt_and_ledgers(self):
        receipt, ledgers = cells.build_cell(
            cell(self._workload()), "run1", "msha", self._console(), PROC,
            "guest1",
        )
        self.assertEqual(receipt["cell_id"], "D01")
        self.assertTrue(all(receipt["checks"].values()),
                        receipt["checks"])
        self.assertEqual(receipt["observation"], {"expected": 4, "actual": 4})
        self.assertIn("workload-ledger.jsonl", ledgers)
        self.assertIn("registry.json", ledgers)
        self.assertIn("product-report.json", ledgers)
        ledger_rows = ledgers["workload-ledger.jsonl"].strip().split("\n")
        self.assertEqual(len(ledger_rows), 4)

    def test_d01_alloc_names_records_bound_names(self):
        receipt, _ = cells.build_cell(
            cell(self._workload()), "run1", "msha", self._console(), PROC,
            "guest1",
        )
        self.assertEqual(receipt["alloc_names"],
                         {"d01-generic": ["cbc(aes)"],
                          "d01-driver": ["cbc(aes)"]})

    def test_d01_alloc_names_records_fallback_names(self):
        # No-AES CPUs refuse the generic bind; the guest then binds
        # the exact driver for the generic half. The receipt must
        # record the fallback, not hide it.
        lines = list(PRELUDE_MARKS)
        lines += [
            registry("cbc(aes)", "cbc-aes-generic", 100),
            'DEMO:PROBE {"fact": "selected", "name": "cbc(aes)",'
            ' "driver": "cbc-aes-generic", "type": "skcipher"}',
            'DEMO:PROBE {"fact": "bind-probe", "name": "cbc(aes)",'
            ' "ok": false, "ts_mono": 2.6}',
            mark("KRYPROBE-START", 2.5),
            mark("WORKLOAD-START", 3.0),
        ]
        ts = 4.0
        for seq in range(2):
            lines.append(ledger(seq, "d01-generic", ts=round(ts, 1),
                                name="cbc-aes-generic"))
            ts += 0.1
        for seq in range(2):
            lines.append(ledger(seq, "d01-driver", ts=round(ts, 1),
                                name="cbc-aes-generic"))
            ts += 0.1
        lines += [mark("WORKLOAD-STOP", ts), mark("WORKLOAD-DONE", ts + 1)]
        lines.append(KRYPROBE_EXIT)
        console = "[ 0.1] noise\n" + "\n".join(lines) + "\n" + KREPO
        receipt, _ = cells.build_cell(
            cell(self._workload()), "run1", "msha", console, PROC, "guest1")
        self.assertTrue(all(receipt["checks"].values()),
                        receipt["checks"])
        self.assertEqual(receipt["alloc_names"],
                         {"d01-generic": ["cbc-aes-generic"],
                          "d01-driver": ["cbc-aes-generic"]})

    def test_d01_short_count_fails(self):
        receipt, _ = cells.build_cell(
            cell(self._workload()), "run1", "msha",
            self._console().replace(ledger(1, "d01-driver", ts=4.3) + "\n", ""),
            PROC, "guest1",
        )
        self.assertFalse(all(receipt["checks"].values()))

    def test_d01_failing_status_fails(self):
        bad = self._console().replace('"status": 0', '"status": -5', 1)
        receipt, _ = cells.build_cell(
            cell(self._workload()), "run1", "msha", bad, PROC, "guest1")
        self.assertFalse(receipt["checks"]["all_status_ok"])

    def test_d01_missing_kryprobe_fails(self):
        console = self._console().split("DEMO:KRYPROBE-BEGIN")[0]
        receipt, _ = cells.build_cell(
            cell(self._workload()), "run1", "msha", console, PROC, "guest1")
        self.assertFalse(receipt["checks"]["kryprobe_present"])

    def test_d01_unknown_selected_driver_fails(self):
        console = self._console().replace(
            '"driver": "cbc-aes-aesni"}', '"driver": "no-such"}')
        receipt, _ = cells.build_cell(
            cell(self._workload()), "run1", "msha", console, PROC, "guest1")
        self.assertFalse(receipt["checks"]["selected_in_registry"])

    def test_console_parse_error_fails_cell(self):
        receipt, _ = cells.build_cell(
            cell(self._workload()), "run1", "msha",
            "DEMO:FROB {}\n", PROC, "guest1")
        self.assertFalse(all(receipt["checks"].values()))
        self.assertIn("console", receipt["checks"])


class D02Tests(unittest.TestCase):
    def _console(self):
        lines = list(PRELUDE_MARKS)
        lines += [
            registry("cbc(aes)", "cbc-aes-generic", 100),
            'DEMO:PROBE {"fact": "selected", "name": "cbc(aes)",'
            ' "driver": "cbc-aes-generic"}',
            'DEMO:CPU {"flags": " fpu no-aes "}',
            mark("KRYPROBE-START", 2.5),
            mark("WORKLOAD-START", 3.0),
            'DEMO:HANDLE {"event": "held", "alloc_id": "d02-held",'
            ' "ts_mono": 3.5}',
            ledger(0, "d02-fresh0", ts=4.0),
            ledger(1, "d02-fresh0", ts=4.1),
            ledger(0, "d02-fresh1", ts=4.2),
            ledger(1, "d02-fresh1", ts=4.3),
            'DEMO:HANDLE {"event": "released", "alloc_id": "d02-held",'
            ' "ts_mono": 5.0}',
            mark("WORKLOAD-STOP", 6.0),
            mark("WORKLOAD-DONE", 7.0),
            KRYPROBE_EXIT,
        ]
        return "\n".join(lines) + "\n" + KREPO

    def test_d02_bracketed_handle(self):
        workload = {"kind": "cpu-variant", "requests": 4,
                    "block_bytes": 4096, "rate_per_s": 10,
                    "retained_control": True}
        receipt, ledgers = cells.build_cell(
            cell(workload, "D02"), "run1", "msha", self._console(), PROC,
            "guest1",
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertIn("handles.json", ledgers)
        self.assertIn("cpu-flags.txt", ledgers)

    def test_d02_released_before_fresh_fails(self):
        console = self._console().replace(
            '"ts_mono": 5.0}', '"ts_mono": 3.6}')
        workload = {"kind": "cpu-variant", "requests": 4,
                    "block_bytes": 4096, "rate_per_s": 10,
                    "retained_control": True}
        receipt, _ = cells.build_cell(
            cell(workload, "D02"), "run1", "msha", console, PROC, "guest1")
        self.assertFalse(receipt["checks"]["handle_bracketed"])


class D03Tests(unittest.TestCase):
    def test_d03_io_and_dmap(self):
        lines = list(PRELUDE_MARKS)
        lines += [
            mark("KRYPROBE-START", 2.5),
            mark("WORKLOAD-START", 3.0),
            'DEMO:DMAP {"event": "create", "name": "demo-d03",'
            ' "sectors": -1, "status": 0, "ts_mono": 3.1}',
            'DEMO:DMAP {"event": "load", "name": "demo-d03",'
            ' "sectors": 2097152, "status": 0, "ts_mono": 3.2}',
            'DEMO:DMAP {"event": "resume", "name": "demo-d03",'
            ' "sectors": 1, "status": 0, "ts_mono": 3.3}',
            'DEMO:IO {"phase": "write", "bytes": 67108864,'
            ' "status": 0, "ts_mono": 4.0}',
            'DEMO:IO {"phase": "fsync", "bytes": 67108864,'
            ' "status": 0, "ts_mono": 4.5}',
            'DEMO:IO {"phase": "read", "bytes": 67108864,'
            ' "status": 0, "ts_mono": 5.0}',
            'DEMO:IO {"phase": "verify", "bytes": 67108864,'
            ' "status": 0, "match": true, "ts_mono": 5.1}',
            mark("WORKLOAD-STOP", 6.0),
            'DEMO:DMAP {"event": "remove", "name": "demo-d03",'
            ' "sectors": 0, "status": 0, "ts_mono": 6.1}',
            mark("WORKLOAD-DONE", 7.0),
            KRYPROBE_EXIT,
        ]
        workload = {"kind": "dmcrypt-io", "bytes_each_direction": 67108864,
                    "block_bytes": 4096, "needs_data_disk": True}
        receipt, ledgers = cells.build_cell(
            cell(workload, "D03"), "run1", "msha",
            "\n".join(lines) + "\n" + KREPO, PROC, "guest1",
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertEqual(receipt["observation"],
                         {"expected": 67108864, "actual": 67108864})
        self.assertIn("io-ledger.json", ledgers)

    def test_d03_mismatch_fails(self):
        workload = {"kind": "dmcrypt-io", "bytes_each_direction": 67108864,
                    "block_bytes": 4096, "needs_data_disk": True}
        lines = "\n".join(PRELUDE_MARKS + [
            mark("WORKLOAD-START", 3.0),
            'DEMO:IO {"phase": "verify", "bytes": 10,'
            ' "status": 0, "match": false, "ts_mono": 5.1}',
        ])
        receipt, _ = cells.build_cell(
            cell(workload, "D03"), "run1", "msha", lines, PROC, "guest1")
        self.assertFalse(all(receipt["checks"].values()))


class D04Tests(unittest.TestCase):
    def _console(self, virtio=True, alloc_ok=True):
        lines = list(PRELUDE_MARKS)
        if virtio:
            lines += [
                'DEMO:VIRTIO {"dev": "0000:01:00.0",'
                ' "driver": "virtio_crypto", "queue_proof": false}',
                'DEMO:PROBE {"fact": "virtio-driver",'
                ' "driver": "cbc-virtio"}',
            ]
        else:
            lines += ['DEMO:PROBE {"fact": "virtio-driver", "driver": ""}']
        lines.append(mark("KRYPROBE-START", 2.5))
        lines.append(mark("WORKLOAD-START", 3.0))
        if virtio and alloc_ok:
            lines.append(ledger(0, "d04-virtio", ts=3.5))
        lines.append(
            'DEMO:PROBE {"fact": "virtio-alloc", "ok": %s}'
            % ("true" if alloc_ok else "false"))
        lines.append(ledger(0, "d04-generic", ts=4.0))
        lines += [mark("WORKLOAD-STOP", 5.0), mark("WORKLOAD-DONE", 6.0),
                  KRYPROBE_EXIT]
        # Live D04 shape: the virtio half reports queued (async
        # backend), the generic control half returned-ok.
        specs = [("cbc-aes-aesni", 1, 1, 0)]
        if virtio and alloc_ok:
            specs.insert(0, ("cbc-virtio", 1, 0, 1))
        return "\n".join(lines) + "\n" + krepo_drivers(specs)

    def _workload(self):
        return {"kind": "virtio-device", "devices": 1, "virtio_ops": 1,
                "control_ops": 1, "rate_per_s": 10,
                "block_bytes": 4096}

    def test_d04_stops_at_driver_selection(self):
        receipt, ledgers = cells.build_cell(
            cell(self._workload(), "D04"), "run1", "msha",
            self._console(), PROC, "guest1",
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertEqual(receipt["device"], "unknown")
        self.assertIn("queue-reference.json", ledgers)
        queue = json.loads(ledgers["queue-reference.json"])
        self.assertFalse(queue["queue_proof"])
        # The async virtio half is queued-not-returned; the split
        # is recorded, and the driver row proves product-side
        # selection.
        self.assertTrue(receipt["checks"]["product_virtio_seen"])
        self.assertEqual(receipt["virtio_product"],
                         {"calls": 1, "ok": 0, "queued": 1,
                          "bytes": 4096, "errors": 0})

    def test_d04_unseen_virtio_traffic_fails(self):
        # Alloc succeeded but the product shows no virtio driver
        # row: selection uncorroborated, the claim fails.
        lines = self._console().split("DEMO:KRYPROBE-BEGIN")[0]
        console = lines + krepo_drivers([("cbc-aes-aesni", 1, 1, 0)])
        receipt, _ = cells.build_cell(
            cell(self._workload(), "D04"), "run1", "msha", console, PROC,
            "guest1",
        )
        self.assertFalse(receipt["checks"]["product_virtio_seen"])
        self.assertIsNone(receipt["virtio_product"])

    def test_d04_failed_alloc_still_judged(self):
        receipt, _ = cells.build_cell(
            cell(self._workload(), "D04"), "run1", "msha",
            self._console(alloc_ok=False), PROC, "guest1",
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertFalse(receipt["virtio_alloc_ok"])

    def test_d04_absent_device_is_unsupported(self):
        receipt, ledgers = cells.build_cell(
            cell(self._workload(), "D04"), "run1", "msha",
            self._console(virtio=False), PROC, "guest1",
        )
        self.assertEqual(receipt["verdict"], "UNSUPPORTED")
        self.assertTrue(receipt["reason"])
        self.assertTrue(receipt["positive_control"])
        # The honest absence still seals its (empty-finding) ledgers.
        self.assertIn("device-ledger.json", ledgers)
        self.assertIn("queue-reference.json", ledgers)


class D05Tests(unittest.TestCase):
    def _console(self, fresh_ok=True):
        lines = list(PRELUDE_MARKS)
        lines += [
            'DEMO:VIRTIO {"dev": "0000:01:00.0",'
            ' "driver": "virtio_crypto", "phase": "before"}',
            mark("QUIESCED", 3.0),
            mark("REMOVAL-OBSERVED", 4.0),
        ]
        if fresh_ok:
            lines.append(ledger(0, "d05-fresh", ts=4.5))
        else:
            lines.append(ledger(0, "d05-fresh", status=-19, ts=4.5))
        lines += [
            'DEMO:PROBE {"fact": "post-removal-alloc", "ok": %s}'
            % ("true" if fresh_ok else "false"),
            'DEMO:PROBE {"fact": "selected", "name": "cbc(aes)",'
            ' "driver": "cbc-aes-generic"}',
            mark("WORKLOAD-DONE", 6.0),
        ]
        return "\n".join(lines) + "\n"

    def _extra(self):
        return {
            "expected_device": "crypto0",
            "qmp_events": [
                {"event": "DEVICE_DELETED",
                 "data": {"device": "crypto0", "path": "/x"}},
            ],
        }

    def _workload(self):
        return {"kind": "device-removal", "mode": "quiesced", "post_ops": 1}

    def test_d05_reselection_recorded(self):
        receipt, ledgers = cells.build_cell(
            cell(self._workload(), "D05"), "run1", "msha",
            self._console(), PROC, "guest1", extra=self._extra(),
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertIn("removal-ledger.json", ledgers)
        self.assertIn("qmp-events.jsonl", ledgers)
        self.assertFalse(receipt["removal"]["implies_failover"])

    def test_d05_refusal_recorded(self):
        receipt, _ = cells.build_cell(
            cell(self._workload(), "D05"), "run1", "msha",
            self._console(fresh_ok=False), PROC, "guest1",
            extra=self._extra(),
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertIn("errno", receipt["removal"]["observed"])

    def test_d05_bind_refusal_without_rows_recorded(self):
        lines = list(PRELUDE_MARKS)
        lines += [
            'DEMO:VIRTIO {"dev": "0000:01:00.0",'
            ' "driver": "virtio_crypto", "phase": "before"}',
            mark("QUIESCED", 3.0),
            mark("REMOVAL-OBSERVED", 4.0),
            # No d05-fresh LEDGER rows: the bind itself refused.
            'DEMO:PROBE {"fact": "post-removal-alloc", "ok": false}',
            'DEMO:PROBE {"fact": "selected", "name": "cbc(aes)",'
            ' "driver": ""}',
            mark("WORKLOAD-DONE", 6.0),
        ]
        receipt, _ = cells.build_cell(
            cell(self._workload(), "D05"), "run1", "msha",
            "\n".join(lines) + "\n", PROC, "guest1",
            extra=self._extra(),
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertEqual(receipt["removal"]["observed"], "unfinished")

    def test_d05_missing_qmp_event_fails(self):
        extra = {"expected_device": "crypto0", "qmp_events": []}
        receipt, _ = cells.build_cell(
            cell(self._workload(), "D05"), "run1", "msha",
            self._console(), PROC, "guest1", extra=extra,
        )
        self.assertFalse(receipt["checks"]["qmp_event_present"])

    def test_d05_qmp_error_fails(self):
        extra = dict(self._extra())
        extra["qmp_error"] = "QMP closed waiting for DEVICE_DELETED"
        extra["qmp_events"] = []
        receipt, _ = cells.build_cell(
            cell(self._workload(), "D05"), "run1", "msha",
            self._console(), PROC, "guest1", extra=extra,
        )
        self.assertFalse(receipt["checks"]["qmp_ok"])


class D07Tests(unittest.TestCase):
    def test_d07_unlock_after_attach(self):
        lines = list(PRELUDE_MARKS)
        lines += [
            mark("KRYPROBE-START", 9.0),
            mark("ATTACH-READY", 10.0),
            mark("UNLOCK-START", 11.0),
            'DEMO:DMAP {"event": "create", "name": "demo-d07",'
            ' "sectors": -1, "status": 0, "ts_mono": 11.1}',
            'DEMO:DMAP {"event": "load", "name": "demo-d07",'
            ' "sectors": 2097152, "status": 0, "ts_mono": 11.2}',
            'DEMO:DMAP {"event": "resume", "name": "demo-d07",'
            ' "sectors": 1, "status": 0, "ts_mono": 11.3}',
            mark("UNLOCK-DONE", 12.0),
            'DEMO:IO {"phase": "write", "bytes": 16777216,'
            ' "status": 0, "ts_mono": 13.0}',
            'DEMO:IO {"phase": "fsync", "bytes": 16777216,'
            ' "status": 0, "ts_mono": 13.5}',
            'DEMO:IO {"phase": "read", "bytes": 16777216,'
            ' "status": 0, "ts_mono": 14.0}',
            'DEMO:IO {"phase": "verify", "bytes": 16777216,'
            ' "status": 0, "match": true, "ts_mono": 14.1}',
            'DEMO:DMAP {"event": "remove", "name": "demo-d07",'
            ' "sectors": 0, "status": 0, "ts_mono": 14.2}',
            mark("WORKLOAD-STOP", 15.0),
            mark("WORKLOAD-DONE", 16.0),
            KRYPROBE_EXIT,
        ]
        workload = {"kind": "early-boot", "observer": "early",
                    "io_bytes": 16777216}
        receipt, ledgers = cells.build_cell(
            cell(workload, "D07"), "run1", "msha",
            "\n".join(lines) + "\n" + KREPO, PROC, "guest1",
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertIn("attach-ready.json", ledgers)
        attach = json.loads(ledgers["attach-ready.json"])
        self.assertLess(attach["attach_ts"], attach["unlock_ts"])
        self.assertEqual(attach["unobserved"]["mark"], "UNOBSERVED")

    def test_d07_unlock_before_attach_fails(self):
        lines = "\n".join(PRELUDE_MARKS + [
            mark("UNLOCK-START", 11.0),
            mark("ATTACH-READY", 12.0),
        ])
        workload = {"kind": "early-boot", "observer": "early",
                    "io_bytes": 16777216}
        receipt, _ = cells.build_cell(
            cell(workload, "D07"), "run1", "msha", lines, PROC, "guest1")
        self.assertFalse(receipt["checks"]["unlock_after_attach"])


class D08Tests(unittest.TestCase):
    def _console(self):
        lines = list(PRELUDE_MARKS)
        lines.append(mark("KRYPROBE-START", 3.0))
        lines.append(ledger(0, "d08-w0", ts=4.0))
        lines.append(
            'DEMO:SOAK {"window": 0, "ops_ok": true,'
            ' "kryprobe_exit": 0, "report_lines": 10}')
        lines.append(mark("KRYPROBE-START", 59.0))
        lines.append(mark("STOP-WINDOW-START", 60.0))
        lines.append(ledger(0, "d08-stop", ts=61.0))
        lines.append(mark("STOP-WINDOW-END", 62.0))
        lines.append(
            'DEMO:SOAK {"window": 1, "ops_ok": true,'
            ' "kryprobe_exit": 0, "report_lines": 10,'
            ' "traffic_active_at_stop": true}')
        lines.append(mark("WORKLOAD-DONE", 63.0))
        lines.append(KRYPROBE_EXIT)
        return "\n".join(lines) + "\n" + krepo(1)

    def test_d08_windows_and_stop(self):
        workload = {"kind": "stop-soak", "aggregate_minutes": 20,
                    "windows": 2, "window_ops": 1, "rate_per_s": 10,
                    "block_bytes": 4096}
        receipt, ledgers = cells.build_cell(
            cell(workload, "D08"), "run1", "msha", self._console(), PROC,
            "guest1",
        )
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])
        self.assertIn("soak-windows.json", ledgers)
        self.assertIn("stop-receipt.json", ledgers)
        stop = json.loads(ledgers["stop-receipt.json"])
        self.assertTrue(stop["traffic_active_at_stop"])

    def test_d08_failed_window_fails(self):
        console = self._console().replace(
            '"window": 0, "ops_ok": true', '"window": 0, "ops_ok": false')
        workload = {"kind": "stop-soak", "aggregate_minutes": 20,
                    "windows": 2, "window_ops": 1, "rate_per_s": 10,
                    "block_bytes": 4096}
        receipt, _ = cells.build_cell(
            cell(workload, "D08"), "run1", "msha", console, PROC, "guest1")
        self.assertFalse(all(receipt["checks"].values()))


class ProductReconcileTests(unittest.TestCase):
    def _console(self, workload_ops=4, product_calls=4, errors=0,
                 kexit=0, kverdict="observed", kmissing=(),
                 with_kstart=True):
        lines = list(PRELUDE_MARKS)
        lines += [
            registry("cbc(aes)", "cbc-aes-aesni", 400),
            'DEMO:PROBE {"fact": "selected", "name": "cbc(aes)",'
            ' "driver": "cbc-aes-aesni"}',
        ]
        if with_kstart:
            lines.append(mark("KRYPROBE-START", 2.5))
        lines.append(mark("WORKLOAD-START", 3.0))
        ts = 4.0
        for seq in range(workload_ops // 2):
            lines.append(ledger(seq, "d01-generic", ts=round(ts, 1)))
            ts += 0.1
        for seq in range(workload_ops // 2):
            lines.append(ledger(seq, "d01-driver", ts=round(ts, 1)))
            ts += 0.1
        lines += [mark("WORKLOAD-STOP", round(ts, 1)),
                  mark("WORKLOAD-DONE", round(ts + 1, 1))]
        lines.append(
            'DEMO:PROBE {"fact": "kryprobe-exit", "exit": %d}' % kexit)
        body = ("\n".join(lines) + "\n"
                + krepo(product_calls, errors=errors, verdict=kverdict,
                        missing=kmissing))
        return body

    def _workload(self, ops=4):
        return {"kind": "provider-selection", "requests": ops,
                "block_bytes": 4096, "rate_per_s": 10}

    def _build(self, **kwargs):
        ops = kwargs.pop("workload_ops", 4)
        return cells.build_cell(
            cell(self._workload(ops)), "run1", "msha",
            self._console(workload_ops=ops, **kwargs), PROC, "guest1")

    def test_product_suffix_exact_passes(self):
        receipt, _ = self._build()
        for name in ("product_internal", "product_suffix",
                     "product_verdict", "product_exit_ok"):
            self.assertTrue(receipt["checks"][name], name)
        self.assertEqual(receipt["product"]["missed"], 0)

    def test_product_suffix_within_attach_window_passes(self):
        # Product attached late and missed one op: inside the
        # (window + slack) bound, still an honest suffix.
        receipt, _ = self._build(workload_ops=4, product_calls=3)
        self.assertTrue(receipt["checks"]["product_suffix"])
        self.assertEqual(receipt["product"]["missed"], 1)

    def test_product_overcount_fails(self):
        receipt, _ = self._build(workload_ops=4, product_calls=5)
        self.assertFalse(receipt["checks"]["product_suffix"])

    def test_product_errors_fail(self):
        receipt, _ = self._build(errors=1)
        self.assertFalse(receipt["checks"]["product_internal"])

    def test_product_exit_1_fails(self):
        receipt, _ = self._build(kexit=1)
        self.assertFalse(receipt["checks"]["product_exit_ok"])

    def test_product_partial_with_structural_gaps_passes(self):
        receipt, _ = self._build(
            kexit=3, kverdict="partial",
            kmissing=("capture-integrity", "completion"))
        self.assertTrue(receipt["checks"]["product_verdict"])
        self.assertTrue(receipt["checks"]["product_exit_ok"])

    def test_product_partial_with_attach_gap_fails(self):
        receipt, _ = self._build(
            kexit=3, kverdict="partial", kmissing=("attach",))
        self.assertFalse(receipt["checks"]["product_verdict"])

    def test_missing_kryprobe_start_fails(self):
        receipt, _ = self._build(with_kstart=False)
        self.assertFalse(receipt["checks"]["product_suffix"])

    def test_d08_exit3_window_accepted(self):
        workload = {"kind": "stop-soak", "aggregate_minutes": 20,
                    "windows": 2, "window_ops": 1, "rate_per_s": 10,
                    "block_bytes": 4096}
        lines = list(PRELUDE_MARKS)
        lines.append(mark("KRYPROBE-START", 3.0))
        lines.append(ledger(0, "d08-w0", ts=4.0))
        lines.append(
            'DEMO:SOAK {"window": 0, "ops_ok": true,'
            ' "kryprobe_exit": 3, "report_lines": 10}')
        lines.append(mark("KRYPROBE-START", 59.0))
        lines.append(mark("STOP-WINDOW-START", 60.0))
        lines.append(ledger(0, "d08-stop", ts=61.0))
        lines.append(mark("STOP-WINDOW-END", 62.0))
        lines.append(
            'DEMO:SOAK {"window": 1, "ops_ok": true,'
            ' "kryprobe_exit": 0, "report_lines": 10,'
            ' "traffic_active_at_stop": true}')
        lines.append(mark("WORKLOAD-DONE", 63.0))
        lines.append(KRYPROBE_EXIT)
        receipt, _ = cells.build_cell(
            cell(workload, "D08"), "run1", "msha",
            "\n".join(lines) + "\n" + krepo(1), PROC, "guest1")
        self.assertTrue(all(receipt["checks"].values()), receipt["checks"])

    def test_d08_exit1_window_refused(self):
        workload = {"kind": "stop-soak", "aggregate_minutes": 20,
                    "windows": 2, "window_ops": 1, "rate_per_s": 10,
                    "block_bytes": 4096}
        lines = list(PRELUDE_MARKS)
        lines.append(mark("KRYPROBE-START", 3.0))
        lines.append(ledger(0, "d08-w0", ts=4.0))
        lines.append(
            'DEMO:SOAK {"window": 0, "ops_ok": true,'
            ' "kryprobe_exit": 1, "report_lines": 10}')
        lines.append(mark("KRYPROBE-START", 59.0))
        lines.append(mark("STOP-WINDOW-START", 60.0))
        lines.append(ledger(0, "d08-stop", ts=61.0))
        lines.append(mark("STOP-WINDOW-END", 62.0))
        lines.append(
            'DEMO:SOAK {"window": 1, "ops_ok": true,'
            ' "kryprobe_exit": 0, "report_lines": 10,'
            ' "traffic_active_at_stop": true}')
        lines.append(mark("WORKLOAD-DONE", 63.0))
        lines.append(KRYPROBE_EXIT)
        receipt, _ = cells.build_cell(
            cell(workload, "D08"), "run1", "msha",
            "\n".join(lines) + "\n" + krepo(1), PROC, "guest1")
        self.assertFalse(receipt["checks"]["windows_ok"])


class DispatchTests(unittest.TestCase):
    def test_unknown_kind_refuses(self):
        with self.assertRaises(cells.CellError):
            cells.build_cell(
                cell({"kind": "frob"}), "run1", "msha", "", PROC, "guest1")

    def test_d06_unsupported_receipt(self):
        receipt = cells.unsupported_receipt(
            cell({"kind": "nested-fallback"}, "D06"), "run1", "x01 absent")
        self.assertEqual(receipt["verdict"], "UNSUPPORTED")
        self.assertTrue(receipt["positive_control"])

    def test_evidence_cover_matches(self):
        got = cells.check_evidence_cover({
            "id": "D01", "workload": {"kind": "provider-selection"},
            "expected_evidence": ["workload-ledger.jsonl", "registry.json",
                                  "product-report.json", "cell-D01.json"],
        })
        self.assertEqual(len(got), 4)

    def test_evidence_skew_refused(self):
        with self.assertRaises(cells.CellError):
            cells.check_evidence_cover({
                "id": "D01", "workload": {"kind": "provider-selection"},
                "expected_evidence": ["cell-D01.json"],
            })

    def test_ledger_names_cover_expected_evidence(self):
        for kind, cell_id in [
            ("provider-selection", "D01"), ("cpu-variant", "D02"),
            ("dmcrypt-io", "D03"), ("virtio-device", "D04"),
            ("device-removal", "D05"), ("early-boot", "D07"),
            ("stop-soak", "D08"),
        ]:
            names = cells.ledger_names({"kind": kind})
            self.assertTrue(names, kind)
            self.assertIn(f"cell-{cell_id}.json", names, kind)


if __name__ == "__main__":
    unittest.main()
