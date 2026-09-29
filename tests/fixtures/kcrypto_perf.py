#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T14 P9 performance workload driver (test-only, committed fixture).

Sustained kernel-crypto traffic with an independent per-op ledger:
AF_ALG skcipher/aead roundtrips with monotonic per-call timestamps,
or kernel-fixture async GO loops (blocking GO <=> terminal covered).

Usage:
    kcrypto_perf.py <class> <size> <meas_s> <warmup_s> [options] <ledger.csv>
    class: skcipher | aead | async
    options: --bulk (no per-op rows: perturbation control),
             --paced N (fixed N ops/s cadence),
             --threads T (T worker threads, own socket each; AF_ALG only),
             --control PATH (fixture control; async only,
                 default /sys/kernel/debug/kcrypto_fixture/control)

Writes <ledger.csv> (header + measurement-window rows only,
``seq,phase,op,dt_ns``) and <ledger.csv.summary.json>. Deterministic
patterns; seq-derived IVs; roundtrip asserted in-process. Exit 0 on
success, 1 on workload failure, 2 on usage error.
"""

import json
import os
import socket
import struct
import sys
import threading
import time

ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0
ALG_OP_ENCRYPT = 1

FIXTURE_CONTROL = "/sys/kernel/debug/kcrypto_fixture/control"
CHUNK_ROWS = 16384


def pattern(size, seed):
    return bytes((seed + i) & 0xFF for i in range(size))


def iv_for(seq):
    return struct.pack("=Q", seq & 0xFFFFFFFFFFFFFFFF) + bytes(8)


def op_cmsg(op, iv):
    return [(socket.SOL_ALG, ALG_SET_OP, struct.pack("=I", op)),
            (socket.SOL_ALG, ALG_SET_IV,
             struct.pack("=I", len(iv)) + iv)]


def send_all(op, data, cmsg):
    # AF_ALG sendmsg may take partial writes on large payloads.
    # MSG_MORE stays set while bytes remain beyond this chunk; the
    # final chunk goes without MORE (a short final take is a loud
    # failure, never a silently truncated op).
    chunk_size = 16384
    off = 0
    first = True
    while off < len(data):
        chunk = data[off:off + chunk_size]
        more = off + len(chunk) < len(data)
        sent = op.sendmsg([chunk], cmsg if first else [],
                          socket.MSG_MORE if more else 0)
        assert sent > 0, "zero sendmsg take"
        if not more:
            assert sent == len(chunk), \
                f"short final sendmsg {sent}/{len(chunk)}"
        off += sent
        first = False


def tune_buffers(sock, need):
    # One AF_ALG op completes only when its last byte arrives, so
    # the socket buffers must hold the whole message; the small
    # default deadlocks 1 MiB ops mid-send.
    want = max(need + 65536, 1048576)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, want)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
    got_s = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    got_r = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    assert got_s >= need and got_r >= need, \
        f"socket buffers too small: snd={got_s} rcv={got_r} need={need}"


class Skcipher:
    op_names = ("encrypt", "decrypt")

    def __init__(self, size):
        self.size = size
        self.msg = pattern(size, 7)
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.bind(("skcipher", "cbc(aes)"))
        sock.setsockopt(socket.SOL_ALG, ALG_SET_KEY, bytes(range(16)))
        self.op, _ = sock.accept()
        self.op.settimeout(30)
        tune_buffers(self.op, size + 65536)
        self.sock = sock

    def roundtrip(self, seq):
        iv = iv_for(seq)
        t0 = time.monotonic_ns()
        send_all(self.op, self.msg, op_cmsg(ALG_OP_ENCRYPT, iv))
        ct = self.op.recv(self.size + 64)
        t1 = time.monotonic_ns()
        send_all(self.op, ct, op_cmsg(ALG_OP_DECRYPT, iv))
        pt = self.op.recv(self.size + 64)
        t2 = time.monotonic_ns()
        assert pt == self.msg, f"roundtrip mismatch seq={seq}"
        return [("encrypt", t0, t1, 0), ("decrypt", t1, t2, 0)]

    def close(self):
        self.op.close()
        self.sock.close()


class Aead:
    ASSOC = 32
    TAG = 16
    op_names = ("encrypt", "decrypt")

    def __init__(self, size):
        self.size = size
        self.assoc = pattern(self.ASSOC, 3)
        self.msg = pattern(size, 7)
        sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        sock.bind(("aead", "gcm(aes)"))
        sock.setsockopt(socket.SOL_ALG, ALG_SET_KEY, bytes(range(16)))
        # AUTHSIZE takes the *length* of the option buffer as the
        # value (kernel: setauthsize(private, optlen)).
        sock.setsockopt(socket.SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
                        bytes(self.TAG))
        self.op, _ = sock.accept()
        self.op.settimeout(30)
        tune_buffers(self.op, self.ASSOC + size + self.TAG + 65536)
        self.sock = sock

    def _cmsg(self, op, iv):
        return op_cmsg(op, iv) + [
            (socket.SOL_ALG, ALG_SET_AEAD_ASSOCLEN,
             struct.pack("=I", self.ASSOC))]

    def roundtrip(self, seq):
        iv = bytes(12)
        t0 = time.monotonic_ns()
        send_all(self.op, self.assoc + self.msg, self._cmsg(1, iv))
        # AEAD recv echoes ASSOC || CIPHERTEXT || TAG.
        enc_out = self.op.recv(self.ASSOC + self.size + self.TAG + 64)
        assert len(enc_out) == self.ASSOC + self.size + self.TAG, \
            f"aead ct length {len(enc_out)} seq={seq}"
        assert enc_out[:self.ASSOC] == self.assoc, \
            f"aead assoc echo seq={seq}"
        t1 = time.monotonic_ns()
        # Decrypt takes the encrypt block back as-is (assoc inside).
        send_all(self.op, enc_out, self._cmsg(0, iv))
        dec_out = self.op.recv(self.ASSOC + self.size + 64)
        t2 = time.monotonic_ns()
        assert dec_out[:self.ASSOC] == self.assoc, \
            f"aead dec assoc seq={seq}"
        assert dec_out[self.ASSOC:] == self.msg, \
            f"aead roundtrip mismatch seq={seq}"
        return [("encrypt", t0, t1, 0), ("decrypt", t1, t2, 0)]

    def close(self):
        self.op.close()
        self.sock.close()


class AsyncFixture:
    op_names = ("go",)

    def __init__(self, size, control=FIXTURE_CONTROL):
        del size
        self.control = control
        self.tag = f"t14p-{os.getpid()}"

    def roundtrip(self, seq):
        run_id = f"{self.tag}-{seq}"
        with open(self.control, "w") as fh:
            fh.write(f"PREPARE {run_id} async-once {1000 + seq}\n")
        t0 = time.monotonic_ns()
        # GO runs the scenario synchronously under the fixture run
        # lock and returns only after the terminal wait: a
        # successful write IS terminal-covered latency.
        rc = 0
        try:
            with open(self.control, "w") as fh:
                fh.write("GO\n")
        except OSError as exc:
            rc = exc.errno or 1
        t1 = time.monotonic_ns()
        return [("go", t0, t1, rc)]

    def close(self):
        pass


CLASSES = {"skcipher": Skcipher, "aead": Aead, "async": AsyncFixture}


def parse_args(argv):
    if len(argv) < 6:
        return None
    cls, size_s, meas_s, warm_s = argv[1], argv[2], argv[3], argv[4]
    rest = argv[5:-1]
    ledger = argv[-1]
    if cls not in CLASSES:
        return None
    try:
        size = int(size_s)
        meas = float(meas_s)
        warm = float(warm_s)
    except ValueError:
        return None
    if size <= 0 or meas <= 0 or warm < 0:
        return None
    bulk = False
    paced = 0
    threads = 1
    control = FIXTURE_CONTROL
    i = 0
    while i < len(rest):
        if rest[i] == "--bulk":
            bulk = True
            i += 1
        elif rest[i] == "--paced" and i + 1 < len(rest):
            try:
                paced = int(rest[i + 1])
            except ValueError:
                return None
            if paced <= 0:
                return None
            i += 2
        elif rest[i] == "--threads" and i + 1 < len(rest):
            try:
                threads = int(rest[i + 1])
            except ValueError:
                return None
            if threads <= 0:
                return None
            i += 2
        elif rest[i] == "--control" and i + 1 < len(rest):
            control = rest[i + 1]
            i += 2
        else:
            return None
    if cls == "async" and threads != 1:
        return None
    return {"class": cls, "size": size, "meas": meas, "warm": warm,
            "bulk": bulk, "paced": paced, "threads": threads,
            "control": control, "ledger": ledger}


class Shared:
    def __init__(self):
        self.lock = threading.Lock()
        self.seq = 0
        self.ops_total = 0
        self.ops_meas = 0
        self.rows_meas = 0
        self.fails = 0
        self.late = 0
        self.meas_start = None
        self.buf = []
        self.stop = False


def worker_loop(worker, opts, shared, fh, t_start, warm_end, end):
    period_ns = 1e9 / opts["paced"] if opts["paced"] else 0
    deadline = None
    while True:
        with shared.lock:
            if shared.stop:
                return
            seq = shared.seq
            shared.seq += 1
        now = time.monotonic_ns()
        if now >= end:
            return
        if opts["paced"]:
            if deadline is None:
                deadline = now
            if now < deadline:
                delay = deadline - now
                if delay > 2000:
                    time.sleep((delay - 1000) / 1e9)
                while time.monotonic_ns() < deadline:
                    pass
                now = time.monotonic_ns()
            elif now > deadline + 100000:
                with shared.lock:
                    shared.late += 1
            deadline += period_ns
        phase = "warm" if now < warm_end else "meas"
        try:
            calls = worker.roundtrip(seq)
        except (OSError, AssertionError):
            with shared.lock:
                shared.fails += 1
                shared.stop = True
            return
        with shared.lock:
            shared.ops_total += 1
            if phase == "meas":
                if shared.meas_start is None:
                    shared.meas_start = now
                shared.ops_meas += 1
                if not opts["bulk"]:
                    for op, t0, t1, rc in calls:
                        shared.buf.append(f"{seq},meas,{op},{t1 - t0}\n")
                        shared.rows_meas += 1
                        if rc:
                            shared.fails += 1
                    if len(shared.buf) >= CHUNK_ROWS:
                        fh.write("".join(shared.buf))
                        shared.buf.clear()
                else:
                    for _, _, _, rc in calls:
                        if rc:
                            shared.fails += 1
            else:
                for _, _, _, rc in calls:
                    if rc:
                        shared.fails += 1


def run(opts):
    if opts["class"] == "async":
        workers = [AsyncFixture(opts["size"], opts["control"])]
    else:
        workers = [CLASSES[opts["class"]](opts["size"])
                   for _ in range(opts["threads"])]
    shared = Shared()
    t_start = time.monotonic_ns()
    warm_end = t_start + opts["warm"] * 1e9
    end = t_start + (opts["warm"] + opts["meas"]) * 1e9
    with open(opts["ledger"], "w", newline="") as fh:
        fh.write("seq,phase,op,dt_ns\n")
        threads = [threading.Thread(target=worker_loop,
                                    args=(worker, opts, shared, fh,
                                          t_start, warm_end, end))
                   for worker in workers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if shared.buf:
            fh.write("".join(shared.buf))
            shared.buf.clear()
    t_end = time.monotonic_ns()
    for worker in workers:
        worker.close()
    meas_start = shared.meas_start
    if meas_start is None:
        meas_start = t_end
    summary = {
        "ops_total": shared.ops_total, "ops_meas": shared.ops_meas,
        "rows_meas": shared.rows_meas, "class": opts["class"],
        "size": opts["size"], "t_warm_start_ns": t_start,
        "t_meas_start_ns": meas_start, "t_end_ns": t_end,
        "meas_window_s": (t_end - meas_start) / 1e9,
        "bulk": opts["bulk"], "paced": opts["paced"],
        "threads": opts["threads"],
        "offered": shared.ops_total, "late": shared.late,
        "pattern": "seq8", "iv": "seq64", "fails": shared.fails,
        "rc": 0 if shared.fails == 0 else 1, "timed_out": False,
    }
    if opts["class"] == "aead":
        summary["assoc"] = Aead.ASSOC
        summary["tag"] = Aead.TAG
    with open(opts["ledger"] + ".summary.json", "w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    print(f"driver done: ops={shared.ops_total} meas={shared.ops_meas} "
          f"rows={shared.rows_meas} fails={shared.fails} "
          f"late={shared.late} wall_s={(t_end - t_start) / 1e9:.1f}",
          flush=True)
    return 0 if shared.fails == 0 else 1


def main(argv):
    opts = parse_args(argv)
    if opts is None:
        print("usage: kcrypto_perf.py <skcipher|aead|async> <size> "
              "<meas_s> <warmup_s> [--bulk] [--paced N] [--threads T] "
              "[--control PATH] <ledger.csv>", file=sys.stderr)
        return 2
    try:
        return run(opts)
    except (OSError, AssertionError) as exc:
        print(f"driver failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
