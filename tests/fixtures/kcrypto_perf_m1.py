#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""M1 early-gate workload driver (test-only, committed fixture).

Byte-identical workload core to T14 P9 ``kcrypto_perf.py`` (same
socket choreography, same ledger format, same summary keys), plus two
multi-process shapes for the M1 §10.2 legs:

- N-cgroup: ``--actors A --cgroups C`` forks A single-threaded actor
  processes across C owned cgroups (A divisible by C). Each child
  moves ITSELF via ``cgroup.procs`` before any crypto (no placement
  race), runs the flat workload, and exits; the parent concatenates
  per-shard ledgers with rewritten globally-unique seqs (pairing
  preserved: enc+dec share their shard seq, hence their global seq).
- churn: ``--churn-every-ms M --churn-ops K`` forks one arrival
  process per M ms on a drift-free monotonic schedule; each arrival
  runs K roundtrips (1 alloc + K enc + K dec ops but only 3 ctx keys
  — one per class, same task) then exits.

Default (no M1 flags) runs the ORIGINAL single-process path
untouched. The merged summary keeps every R1 key (frozen judge
compatible) and adds ``actors``/``cgroups``/``arrivals``/
``child_fails``. Exit 0 on success, 1 on workload failure
(including any child failure or cgroup leftover), 2 on usage error.
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

    def roundtrip_bulk(self, seq):
        # P9R1A-N8: bulk perturbation control — identical
        # crypto work and roundtrip assertion, but NO clock
        # reads (the pre-repair bulk path still paid three
        # timestamps per op, so it bounded row costs only).
        iv = iv_for(seq)
        send_all(self.op, self.msg, op_cmsg(ALG_OP_ENCRYPT, iv))
        ct = self.op.recv(self.size + 64)
        send_all(self.op, ct, op_cmsg(ALG_OP_DECRYPT, iv))
        pt = self.op.recv(self.size + 64)
        assert pt == self.msg, f"roundtrip mismatch seq={seq}"
        return [("encrypt", 0, 0, 0), ("decrypt", 0, 0, 0)]

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

    def roundtrip_bulk(self, seq):
        # P9R1A-N8: bulk perturbation control — identical
        # crypto work and assertions, but NO clock reads.
        iv = bytes(12)
        send_all(self.op, self.assoc + self.msg, self._cmsg(1, iv))
        enc_out = self.op.recv(self.ASSOC + self.size + self.TAG + 64)
        assert len(enc_out) == self.ASSOC + self.size + self.TAG, \
            f"aead ct length {len(enc_out)} seq={seq}"
        assert enc_out[:self.ASSOC] == self.assoc, \
            f"aead assoc echo seq={seq}"
        send_all(self.op, enc_out, self._cmsg(0, iv))
        dec_out = self.op.recv(self.ASSOC + self.size + 64)
        assert dec_out[:self.ASSOC] == self.assoc, \
            f"aead dec assoc seq={seq}"
        assert dec_out[self.ASSOC:] == self.msg, \
            f"aead roundtrip mismatch seq={seq}"
        return [("encrypt", 0, 0, 0), ("decrypt", 0, 0, 0)]

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

    def roundtrip_bulk(self, seq):
        # P9R1A-N8: bulk perturbation control — identical
        # fixture work, but NO clock reads.
        run_id = f"{self.tag}-{seq}"
        with open(self.control, "w") as fh:
            fh.write(f"PREPARE {run_id} async-once {1000 + seq}\n")
        rc = 0
        try:
            with open(self.control, "w") as fh:
                fh.write("GO\n")
        except OSError as exc:
            rc = exc.errno or 1
        return [("go", 0, 0, rc)]

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
    actors = 1
    cgroups = 1
    churn_every_ms = 0
    churn_ops = 0
    shard_dir = None
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
        elif rest[i] == "--actors" and i + 1 < len(rest):
            try:
                actors = int(rest[i + 1])
            except ValueError:
                return None
            if actors <= 0:
                return None
            i += 2
        elif rest[i] == "--cgroups" and i + 1 < len(rest):
            try:
                cgroups = int(rest[i + 1])
            except ValueError:
                return None
            if cgroups <= 0:
                return None
            i += 2
        elif rest[i] == "--churn-every-ms" and i + 1 < len(rest):
            try:
                churn_every_ms = int(rest[i + 1])
            except ValueError:
                return None
            if churn_every_ms <= 0:
                return None
            i += 2
        elif rest[i] == "--churn-ops" and i + 1 < len(rest):
            try:
                churn_ops = int(rest[i + 1])
            except ValueError:
                return None
            if churn_ops <= 0:
                return None
            i += 2
        elif rest[i] == "--shard-dir" and i + 1 < len(rest):
            shard_dir = rest[i + 1]
            if not shard_dir:
                return None
            i += 2
        else:
            return None
    if cls == "async" and threads != 1:
        return None
    m1_multi = actors != 1 or cgroups != 1
    m1_churn = churn_every_ms != 0 or churn_ops != 0
    if m1_multi and m1_churn:
        return None
    if m1_churn and (churn_every_ms == 0 or churn_ops == 0):
        return None
    if m1_multi and (cls == "async" or threads != 1 or paced or bulk):
        return None
    if m1_churn and (cls == "async" or threads != 1 or paced or bulk):
        return None
    if m1_multi and actors % cgroups != 0:
        return None
    return {"class": cls, "size": size, "meas": meas, "warm": warm,
            "bulk": bulk, "paced": paced, "threads": threads,
            "control": control, "ledger": ledger, "actors": actors,
            "cgroups": cgroups, "churn_every_ms": churn_every_ms,
            "churn_ops": churn_ops, "shard_dir": shard_dir}


def _shard_path(opts, tag, idx):
    """One shard ledger path (H-C guest-local transport): with
    ``--shard-dir`` the shard lives under that directory (guest
    local); otherwise it is a ledger sibling, exactly the
    frozen layout. Per-shard ``.summary.json`` files ride
    alongside automatically (same prefix)."""
    base = os.path.basename(opts["ledger"])
    if opts.get("shard_dir"):
        return os.path.join(opts["shard_dir"],
                            f"{base}.{tag}-{idx}")
    return f"{opts['ledger']}.{tag}-{idx}"


def _shard_paths(opts, count, tag):
    """Shard ledger paths ``tag-0..tag-(count-1)`` (see
    ``_shard_path``)."""
    return [_shard_path(opts, tag, idx) for idx in range(count)]


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
            if opts["bulk"]:
                calls = worker.roundtrip_bulk(seq)
            else:
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


M1_CGROUP_BASE = "/sys/fs/cgroup"
M1_CGROUP_TAG = "kprobe-m1-driver"


def _spawn_legacy_child(argv0, opts, shard_ledger, cgroup_dir):
    """Fork+exec one single-actor legacy run; the child moves ITSELF
    into ``cgroup_dir`` (or stays) BEFORE exec, so placement precedes
    the first socket bind by construction (no race). Returns the child
    pid. The child execs this same script WITHOUT M1 flags (legacy
    single-process path, one thread, own shard ledger)."""
    pid = os.fork()
    if pid != 0:
        return pid
    try:
        if cgroup_dir is not None:
            with open(os.path.join(cgroup_dir, "cgroup.procs"), "w") as fh:
                fh.write(str(os.getpid()))
        os.execv(sys.executable, [
            sys.executable, argv0, opts["class"], str(opts["size"]),
            str(opts["meas"]), str(opts["warm"]), shard_ledger])
    except OSError as exc:
        print(f"m1 child setup failed: {exc}", file=sys.stderr)
    os._exit(10)


def _reap_children(pids):
    """Blocking wait for every child pid; returns (failed, worst_rc).
    Any abnormal exit fails the run loudly (fail-closed oracle)."""
    failed = 0
    worst = 0
    for pid in pids:
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            rc = os.WEXITSTATUS(status)
            if rc != 0:
                failed += 1
                worst = max(worst, rc)
        else:
            failed += 1
            worst = max(worst, 128)
    return failed, worst


def _merge_shards(shard_paths, ledger_path):
    """Concatenate shard ledgers with rewritten globally-unique seqs.

    Pairing is preserved: enc+dec share their shard-local seq, hence
    their global seq (offset per shard). Returns
    (ops_total, ops_meas, rows_meas, fails, late, offered,
    t_warm_start_ns, t_meas_start_ns). The merged meas start is the
    min over shards WITH meas ops (warm-only arrivals carry a
    fallback stamp that must not shrink the window); None when no
    shard measured (degenerate — the caller points it at t_end so
    the frozen timing check fails the leg loudly). The merged meas
    MAX (same filter) rides along for actor-skew reporting (N6).
    Raises on any unreadable shard."""
    ops_total = ops_meas = rows_meas = fails = late = offered = 0
    t_warm_start = None
    t_meas_start = None
    t_meas_max = None
    offset = 0
    with open(ledger_path, "w", newline="") as out:
        out.write("seq,phase,op,dt_ns\n")
        for shard in shard_paths:
            with open(shard + ".summary.json") as fh:
                summary = json.load(fh)
            ops_total += summary["ops_total"]
            ops_meas += summary["ops_meas"]
            rows_meas += summary["rows_meas"]
            fails += summary["fails"]
            late += summary["late"]
            offered += summary["offered"]
            t0 = summary["t_warm_start_ns"]
            t_warm_start = t0 if t_warm_start is None else min(t_warm_start, t0)
            if summary["ops_meas"] > 0:
                t1 = summary["t_meas_start_ns"]
                t_meas_start = t1 if t_meas_start is None else min(t_meas_start, t1)
                t_meas_max = t1 if t_meas_max is None else max(t_meas_max, t1)
            shard_max = -1
            with open(shard) as fh:
                header = fh.readline()
                assert header.strip() == "seq,phase,op,dt_ns", \
                    f"shard {shard} header {header!r}"
                for line in fh:
                    seq_s, rest = line.split(",", 1)
                    seq = int(seq_s)
                    shard_max = max(shard_max, seq)
                    out.write(f"{offset + seq},{rest}")
            offset += shard_max + 1
    return (ops_total, ops_meas, rows_meas, fails, late, offered,
            t_warm_start, t_meas_start, t_meas_max)


def _run_n_cgroup(argv0, opts):
    """N-cgroup shape: A actors across C owned cgroups, flat-out."""
    actors = opts["actors"]
    cgroups = opts["cgroups"]
    base = M1_CGROUP_BASE
    if not os.path.isfile(os.path.join(base, "cgroup.controllers")):
        print("m1: cgroup v2 base unavailable", file=sys.stderr)
        return 1
    tag = f"{M1_CGROUP_TAG}-{os.getpid()}"
    dirs = [os.path.join(base, f"{tag}-{i}") for i in range(cgroups)]
    try:
        for path in dirs:
            os.mkdir(path)
    except OSError as exc:
        print(f"m1: cgroup mkdir failed: {exc}", file=sys.stderr)
        return 1
    per_group = actors // cgroups
    shards = _shard_paths(opts, actors, "shard")
    pids = []
    try:
        for i in range(actors):
            group = dirs[(i // per_group) % cgroups]
            pids.append(_spawn_legacy_child(argv0, opts, shards[i], group))
        failed, worst = _reap_children(pids)
        # N6: t_end stamps the reaped workload end BEFORE cgroup
        # teardown — rmdir is parent-side overhead, never workload
        # (same F6 principle as the merge exclusion below).
        t_end = time.monotonic_ns()
    finally:
        leftovers = []
        for path in dirs:
            try:
                os.rmdir(path)
            except OSError:
                leftovers.append(path)
    if leftovers:
        print(f"m1: cgroup leftovers (loud, not silent): {leftovers}",
              file=sys.stderr)
        return 1
    if failed:
        print(f"m1: {failed} actor children failed (worst rc={worst})",
              file=sys.stderr)
        return 1
    # F6: the shard merge runs AFTER t_end — it rewrites the whole
    # ledger (seconds at M1 scale) and must not inflate the measure
    # window. Its own cost rides merge_s.
    try:
        (ops_total, ops_meas, rows_meas, fails, late, offered,
         t_warm_start, t_meas_start,
         t_meas_max) = _merge_shards(shards, opts["ledger"])
    except (OSError, ValueError, AssertionError, KeyError) as exc:
        print(f"m1: shard merge failed: {exc}", file=sys.stderr)
        return 1
    t_merged = time.monotonic_ns()
    if t_meas_start is None:
        t_meas_start = t_end
        t_meas_max = t_end
    summary = {
        "ops_total": ops_total, "ops_meas": ops_meas,
        "rows_meas": rows_meas, "class": opts["class"],
        "size": opts["size"], "t_warm_start_ns": t_warm_start,
        "t_meas_start_ns": t_meas_start, "t_end_ns": t_end,
        "meas_window_s": (t_end - t_meas_start) / 1e9,
        "merge_s": (t_merged - t_end) / 1e9,
        # N6: actor-start skew (max-min shard meas start),
        # informational like merge_s — the stagger from sequential
        # fork+exec plus scheduling jitter. Quiet-canary measured
        # 1.8-2.4 s at 64 actors (leg00A 2.423 s; 30 s legs read
        # ~32 s, margin ~3 s to the 35 s ceiling); the judge does
        # not gate on it (the frozen timing gate already bounds the
        # total window). merge_s (50-67 s at this scale) is likewise
        # excluded from the window but NOT from campaign wall time
        # or the driver timeout (A4 review I4).
        "skew_s": (t_meas_max - t_meas_start) / 1e9,
        "bulk": False, "paced": 0, "threads": actors,
        "offered": offered, "late": late,
        "pattern": "seq8", "iv": "seq64", "fails": fails,
        "rc": 0 if fails == 0 else 1, "timed_out": False,
        "actors": actors, "cgroups": cgroups, "arrivals": 0,
        "child_fails": 0,
    }
    with open(opts["ledger"] + ".summary.json", "w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    for shard in shards:
        try:
            os.unlink(shard)
            os.unlink(shard + ".summary.json")
        except OSError:
            pass
    print(f"driver done: ops={ops_total} meas={ops_meas} "
          f"rows={rows_meas} fails={fails} late={late} "
          f"wall_s={(t_end - t_warm_start) / 1e9:.1f} "
          f"merge_s={(t_merged - t_end) / 1e9:.2f} "
          f"actors={actors} cgroups={cgroups}", flush=True)
    return 0 if fails == 0 else 1


def _churn_arrival_count(opts):
    """Deterministic arrival count: every k with k*every_ms < W*1000
    (W = warm+meas), from the drift-free schedule — no ±1."""
    window_ms = int((opts["warm"] + opts["meas"]) * 1000)
    every = opts["churn_every_ms"]
    return (window_ms + every - 1) // every


def _run_churn(argv0, opts):
    """Churn shape: one arrival per every_ms on a drift-free
    monotonic schedule; each arrival runs churn_ops roundtrips with
    per-op ledger rows, then exits. Same cgroup (identity churn, not
    cgroup churn). Arrival count is deterministic (see
    ``_churn_arrival_count``); any deviation fails loudly."""
    want = _churn_arrival_count(opts)
    t0 = time.monotonic_ns()
    end = t0 + (opts["warm"] + opts["meas"]) * 1e9
    every_ns = opts["churn_every_ms"] * 1_000_000
    shards = []
    pids = []
    arrival = 0
    deadline = t0
    while deadline < end:
        now = time.monotonic_ns()
        if now < deadline:
            delay = deadline - now
            if delay > 2000:
                time.sleep((delay - 1000) / 1e9)
            while time.monotonic_ns() < deadline:
                pass
        shard = _shard_path(opts, "arrival", arrival)
        shards.append(shard)
        pids.append(_spawn_arrival_child(
            opts, shard, t0, opts["churn_ops"]))
        arrival += 1
        deadline += every_ns
    if arrival != want:
        print(f"m1: arrivals {arrival} != deterministic {want}",
              file=sys.stderr)
        return 1
    failed, worst = _reap_children(pids)
    if failed:
        print(f"m1: {failed} arrival children failed (worst rc={worst})",
              file=sys.stderr)
        return 1
    # F6: t_end stamps the workload end (all arrivals reaped),
    # BEFORE the arrival merge — same rule as the n_cgroup path.
    t_end = time.monotonic_ns()
    try:
        # N6: the meas MAX rides along but churn publishes no skew_s
        # (arrival spread across the window is the workload shape,
        # not start overhead — a skew number would mislead).
        (ops_total, ops_meas, rows_meas, fails, late, offered,
         t_warm_start, t_meas_start,
         _t_meas_max) = _merge_shards(shards, opts["ledger"])
    except (OSError, ValueError, AssertionError, KeyError) as exc:
        print(f"m1: arrival merge failed: {exc}", file=sys.stderr)
        return 1
    t_merged = time.monotonic_ns()
    if t_meas_start is None:
        t_meas_start = t_end
    summary = {
        "ops_total": ops_total, "ops_meas": ops_meas,
        "rows_meas": rows_meas, "class": opts["class"],
        "size": opts["size"], "t_warm_start_ns": t_warm_start,
        "t_meas_start_ns": t_meas_start, "t_end_ns": t_end,
        "meas_window_s": (t_end - t_meas_start) / 1e9,
        "merge_s": (t_merged - t_end) / 1e9,
        "bulk": False, "paced": 0, "threads": arrival,
        "offered": offered, "late": late,
        "pattern": "seq8", "iv": "seq64", "fails": fails,
        "rc": 0 if fails == 0 else 1, "timed_out": False,
        "actors": 1, "cgroups": 1, "arrivals": arrival,
        "child_fails": 0,
    }
    with open(opts["ledger"] + ".summary.json", "w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    for shard in shards:
        try:
            os.unlink(shard)
            os.unlink(shard + ".summary.json")
        except OSError:
            pass
    print(f"driver done: ops={ops_total} meas={ops_meas} "
          f"rows={rows_meas} fails={fails} late={late} "
          f"wall_s={(t_end - t_warm_start) / 1e9:.1f} "
          f"merge_s={(t_merged - t_end) / 1e9:.2f} "
          f"arrivals={arrival}", flush=True)
    return 0 if fails == 0 else 1


def _spawn_arrival_child(opts, shard, t0, ops):
    """Fork one arrival: bind once, run ``ops`` roundtrips with the
    same per-op phase/clock rules as ``worker_loop`` (global window),
    write the shard ledger + summary, then ``os._exit``. Returns pid."""
    pid = os.fork()
    if pid != 0:
        return pid
    rc = 1
    try:
        worker = CLASSES[opts["class"]](opts["size"])
        warm_end = t0 + opts["warm"] * 1e9
        ops_total = ops_meas = rows_meas = fails = 0
        meas_start = None
        with open(shard, "w", newline="") as fh:
            fh.write("seq,phase,op,dt_ns\n")
            for seq in range(ops):
                now = time.monotonic_ns()
                phase = "warm" if now < warm_end else "meas"
                try:
                    calls = worker.roundtrip(seq)
                except (OSError, AssertionError):
                    fails += 1
                    break
                ops_total += 1
                if phase == "meas":
                    if meas_start is None:
                        meas_start = now
                    ops_meas += 1
                    for op, t_start, t_end, op_rc in calls:
                        fh.write(f"{seq},meas,{op},{t_end - t_start}\n")
                        rows_meas += 1
                        if op_rc:
                            fails += 1
                else:
                    for _, _, _, op_rc in calls:
                        if op_rc:
                            fails += 1
        worker.close()
        if meas_start is None:
            meas_start = time.monotonic_ns()
        summary = {
            "ops_total": ops_total, "ops_meas": ops_meas,
            "rows_meas": rows_meas, "t_warm_start_ns": t0,
            "t_meas_start_ns": meas_start, "offered": ops_total,
            "fails": fails, "late": 0,
        }
        with open(shard + ".summary.json", "w") as fh:
            json.dump(summary, fh)
        rc = 0 if fails == 0 else 1
    except (OSError, AssertionError) as exc:
        print(f"m1 arrival failed: {exc}", file=sys.stderr)
        rc = 1
    os._exit(rc)


def main(argv):
    opts = parse_args(argv)
    if opts is None:
        print("usage: kcrypto_perf_m1.py <skcipher|aead|async> <size> "
              "<meas_s> <warmup_s> [--bulk] [--paced N] [--threads T] "
              "[--control PATH] [--actors A --cgroups C | "
              "--churn-every-ms M --churn-ops K] <ledger.csv>",
              file=sys.stderr)
        return 2
    try:
        if opts["churn_every_ms"]:
            return _run_churn(argv[0], opts)
        if opts["actors"] != 1 or opts["cgroups"] != 1:
            return _run_n_cgroup(argv[0], opts)
        return run(opts)
    except (OSError, AssertionError) as exc:
        print(f"driver failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
