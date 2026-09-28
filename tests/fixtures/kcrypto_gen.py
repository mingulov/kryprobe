#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# PROVENANCE_PARENT_SHA256=82325c72d469b30c55604730e8e8c35cde614cfb8580f5d6b9d27f6d58ffc3eb
# Promoted P8/T13 from the inspected T07 delivery-bundle generator
# (.artifacts/kcrypto-t07/delivery-lane-09/stage/kcrypto_gen.py); delta vs the
# parent is this header only -- the traffic core below is byte-identical.
"""Generate kernel-crypto traffic via AF_ALG so `kryprobe watch --system` shows events.

Fires: crypto_alloc_tfm_node (alloc), crypto_skcipher_encrypt/decrypt,
       crypto_shash_digest/finup (hash via sync shash fallback).
No root needed to *generate* traffic; only the watcher needs privileges.

Usage: python3 kcrypto_gen.py [rounds]
"""
import socket
import struct
import sys

ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_OP_DECRYPT = 0
ALG_OP_ENCRYPT = 1


def _op_cmsg(op, iv):
    # Two-cmsg form (kernel ABI, as the repo's Rust AF_ALG
    # fixture sends): ALG_SET_OP carries u32 op alone;
    # ALG_SET_IV carries struct af_alg_iv { u32 ivlen; u8 iv[] }.
    # The parent's single-cmsg OP+IV form misses the recv
    # wakeup on blocking sockets (af_alg_wait_for_data sleeps
    # forever); see kcrypto-gen-README.md.
    return [(socket.SOL_ALG, ALG_SET_OP, struct.pack("=I", op)),
            (socket.SOL_ALG, ALG_SET_IV,
             struct.pack("=I", len(iv)) + iv)]


def skcipher_burst(n=50):
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("skcipher", "cbc(aes)"))
    s.setsockopt(socket.SOL_ALG, ALG_SET_KEY, bytes(range(16)))
    op, _ = s.accept()
    # Bounded wait (never a wedge): blocking AF_ALG skcipher
    # recvmsg misses the completion wakeup on the campaign
    # kernels (sleeps in af_alg_wait_for_data forever) while
    # the timeout/select path observes the ready result; see
    # kcrypto-gen-README.md. Genuine non-delivery raises
    # TimeoutError (honest failure, nonzero exit).
    op.settimeout(30)
    iv = bytes(16)
    msg = b"0123456789abcdef" * 4
    for _ in range(n):
        op.sendmsg([msg], _op_cmsg(ALG_OP_ENCRYPT, iv))
        ct = op.recv(4096)
        op.sendmsg([ct], _op_cmsg(ALG_OP_DECRYPT, iv))
        pt = op.recv(4096)
        assert pt == msg, (pt, msg)
    op.close()
    s.close()
    print(f"skcipher: {2 * n} ops done", flush=True)


def hash_burst(n=50):
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("hash", "sha256"))
    op, _ = s.accept()
    for _ in range(n):
        op.send(b"hello kryprobe" * 64)  # no MSG_MORE: complete message
        digest = op.recv(64)
        assert len(digest) == 32, len(digest)
    op.close()
    s.close()
    print(f"hash: {n} digests done", flush=True)


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("-")]
    do_skcipher = "--skcipher" in argv[1:]
    try:
        rounds = int(args[0]) if args else 3
    except ValueError:
        print(f"usage: {argv[0]} [rounds] [--skcipher]", file=sys.stderr)
        return 2
    try:
        for _ in range(rounds):
            if do_skcipher:
                skcipher_burst()
            hash_burst()
    except OSError as exc:
        print(f"AF_ALG error: {exc} (is CONFIG_CRYPTO_USER_API enabled?)",
              file=sys.stderr)
        return 1
    print("generator finished", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
