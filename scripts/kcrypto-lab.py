#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""kcrypto-lab: fixture guest-run orchestrator (T04).

Per kernel: stages the prebuilt fixture .ko, boots a vng guest under
the task VM flock, runs fixture scenarios via debugfs control, pulls
the JSONL ledgers, validates each against its scenario contract with
the testkit guest_ledger test, and writes host receipts.

Ledger truth is validated by the strict Rust parser, never by this
script's own reading: a nonzero validation rc fails the run.

Usage (from the product worktree):
  scripts/kcrypto-lab.py --kernel 6.12.111 --ko 6.12.111=<path/to.ko> \\
      --scenario sync-once --scenario async-once
Env:
  CARGO_TEST_CMD  cargo test invocation (default: "cargo test --locked")
"""
import argparse
import os
import shlex
import shutil
import subprocess
import sys
import time

GUEST_KERNELS = {"6.12.111": "v6.12.111", "7.2.6": "v7.2.6"}
INNER_TMPL = """#!/bin/sh
OUT={out}
rm -f $OUT/ledger-*.jsonl $OUT/status-*.txt $OUT/prepare-*.err $OUT/go-*.err
CTL=/sys/kernel/debug/kcrypto_fixture/control
LED=/sys/kernel/debug/kcrypto_fixture/ledger
insmod $OUT/{ko} run_suffix={suffix} > $OUT/insmod.log 2>&1; echo "insmod_rc=$?" >> $OUT/results-lab.txt
ls /sys/kernel/btf/kcrypto_fixture > $OUT/modbtf.txt 2>&1
for s in {scenarios}; do
  echo "PREPARE {run_prefix}-$s $s 42" > $CTL 2>$OUT/prepare-$s.err; echo "prepare_$s=$?" >> $OUT/results-lab.txt
  echo GO > $CTL 2>$OUT/go-$s.err; echo "go_$s=$?" >> $OUT/results-lab.txt
  cat $CTL > $OUT/status-$s.txt 2>&1
  cp $LED $OUT/ledger-$s.jsonl 2>/dev/null; echo "ledger_${{s}}_bytes=$(wc -c < $OUT/ledger-$s.jsonl 2>/dev/null || echo 0)" >> $OUT/results-lab.txt
done
rmmod kcrypto_fixture >> $OUT/insmod.log 2>&1; echo "rmmod_rc=$?" >> $OUT/results-lab.txt
lsmod | grep -c kcrypto > $OUT/lsmod-after.txt 2>&1 || echo 0 > $OUT/lsmod-after.txt
dmesg | grep -E "kcrypto_fixture|kxcipher" | tail -5 > $OUT/dmesg.txt 2>&1
echo "step=done" >> $OUT/results-lab.txt
"""


def task_guests():
    """Two-stage argv probe (single-pattern grep self-matches)."""
    ps = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True)
    n = 0
    for line in ps.stdout.splitlines():
        if "virtme" in line and "kryprobe" in line and "ps -eo" not in line:
            n += 1
    return n


def run_kernel(args, worktree, kernel, ko_path):
    vng = GUEST_KERNELS[kernel]
    tag = "lab-k" + kernel
    out = os.path.join(args.out_root, tag)
    os.makedirs(out, mode=0o700, exist_ok=True)
    dest_ko = os.path.join(out, "kcrypto_fixture.ko")
    shutil.copyfile(ko_path, dest_ko)
    inner = os.path.join(out, "inner-lab.sh")
    with open(inner, "w") as f:
        f.write(
            INNER_TMPL.format(
                out=out,
                ko="kcrypto_fixture.ko",
                scenarios=" ".join(args.scenario),
                run_prefix=args.run_prefix,
                suffix=args.suffix,
            )
        )
    import glob as _glob

    for stale in _glob.glob(os.path.join(out, "ledger-*.jsonl")) + _glob.glob(
        os.path.join(out, "status-*.txt")
    ) + _glob.glob(os.path.join(out, "prepare-*.err")) + _glob.glob(
        os.path.join(out, "go-*.err")
    ) + [
        os.path.join(out, name)
        for name in (
            "results-lab.txt", "vng-console-lab.log", "insmod.log",
            "modbtf.txt", "dmesg.txt", "lsmod-after.txt",
        )
    ]:
        try:
            os.unlink(stale)
        except FileNotFoundError:
            pass
    receipt = [f"kernel={kernel} vng={vng} started={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"]
    receipt.append(f"ko={dest_ko}")
    receipt.append(f"pre_guests={task_guests()}")
    cmd = [
        "flock", "-w", "600", args.lock, "vng", "--run", vng,
        "--user", "root", "--cpus", "4", "--memory", "4G",
        "--rwdir", out, "--exec", f"sh {inner}",
    ]
    start = time.time()
    with open(os.path.join(out, "vng-console-lab.log"), "w") as console:
        proc = subprocess.run(cmd, stdout=console, stderr=subprocess.STDOUT)
    receipt.append(f"vng_exit={proc.returncode} wall_seconds={int(time.time() - start)}")
    receipt.append(f"post_guests={task_guests()}")
    lock_probe = subprocess.run(["flock", "-n", args.lock, "true"])
    receipt.append(f"lock={'FREE' if lock_probe.returncode == 0 else 'HELD'}")
    ok = proc.returncode == 0
    cargo = shlex.split(os.environ.get("CARGO_TEST_CMD", "cargo test --locked"))
    for scenario in args.scenario:
        ledger = os.path.join(out, f"ledger-{scenario}.jsonl")
        env = dict(
            os.environ,
            KCRYPTO_LEDGER_PATH=ledger,
            KCRYPTO_RUN_ID=f"{args.run_prefix}-{scenario}",
            KCRYPTO_SCENARIO=scenario,
            KCRYPTO_SUFFIX=args.suffix,
        )
        test_cmd = cargo + [
            "-p", "kryprobe-testkit", "--test", "guest_ledger",
            "--", "--ignored",
        ]
        val = subprocess.run(test_cmd, cwd=worktree, env=env, capture_output=True, text=True)
        tail = "\n".join(val.stdout.splitlines()[-2:]) if val.stdout else val.stderr[-200:]
        receipt.append(f"validate_{scenario}_rc={val.returncode} :: {tail}")
        if val.returncode != 0:
            ok = False
        if args.evidence_dir:
            evk = os.path.join(args.evidence_dir, tag)
            os.makedirs(evk, exist_ok=True)
            for name in (
                f"ledger-{scenario}.jsonl",
                f"status-{scenario}.txt",
                "results-lab.txt",
                "modbtf.txt",
                "inner-lab.sh",
                "dmesg.txt",
            ):
                src = os.path.join(out, name)
                if os.path.exists(src):
                    shutil.copyfile(src, os.path.join(evk, f"lab-{name}"))
    if args.evidence_dir:
        with open(os.path.join(args.evidence_dir, tag, "host-receipt-lab.txt"), "w") as f:
            f.write("\n".join(receipt) + "\n")
    if args.json:
        import json

        print(json.dumps({"kernel": kernel, "ok": ok, "receipt": receipt}))
    print(f"== {kernel}: {'OK' if ok else 'FAIL'}")
    print("\n".join(receipt))
    return ok


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    worktree = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=here,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    ws_root = os.path.dirname(os.path.dirname(worktree))
    ap = argparse.ArgumentParser(description="kcrypto fixture lab orchestrator")
    ap.add_argument("--kernel", action="append", choices=sorted(GUEST_KERNELS),
                    default=[], help="guest kernel(s); repeatable (default: all)")
    ap.add_argument("--ko", action="append", default=[],
                    help="K=V prebuilt fixture .ko (repeatable, required per kernel)")
    ap.add_argument("--scenario", action="append", default=[],
                    help="fixture scenario(s); repeatable (default: all eight)")
    ap.add_argument("--out-root", default=os.path.expanduser("~/.cache/kryprobe-vng/kcrypto-t04"))
    ap.add_argument("--lock", default=os.path.join(ws_root, ".artifacts/locks/kcrypto-t04-vm.lock"))
    ap.add_argument("--evidence-dir", default=os.path.join(ws_root, "evidence/kcrypto-t04"))
    ap.add_argument("--json", action="store_true", help="emit machine-readable receipt per kernel")
    ap.add_argument("--run-prefix", default="run")
    ap.add_argument("--suffix", default="t04a")
    args = ap.parse_args()
    kos = {}
    for item in args.ko:
        key, _, val = item.partition("=")
        if not key or not val:
            ap.error(f"bad --ko {item!r}, want K=V")
        kos[key] = val
    kernels = args.kernel or sorted(GUEST_KERNELS)
    if not args.scenario:
        args.scenario = [
            "sync-once", "async-once", "delayed-completion",
            "backlog-accepted", "early-callback", "exact-driver",
            "failed-alloc", "refheld-release",
        ]
    for kernel in kernels:
        if kernel not in kos:
            ap.error(f"missing --ko for {kernel}")
        if not os.path.isfile(kos[kernel]):
            ap.error(f"ko not found: {kos[kernel]}")
    ok = True
    for kernel in kernels:
        ok = run_kernel(args, worktree, kernel, kos[kernel]) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
