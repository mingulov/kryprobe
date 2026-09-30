#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic initramfs writer (newc cpio + gzip, attempt 4).

Same entries in any order always produce the same bytes: entries
are sorted by path, uid/gid/mtime/nlink are fixed (0/0/0/1, dirs
nlink 2), and the gzip wrapper carries mtime=0. Absolute paths and
``..`` escapes refuse. Used by ``build_initramfs.py`` so the
frozen initramfs hash binds content, not build time.
"""

from __future__ import annotations

import gzip
import stat
from dataclasses import dataclass


class CpioError(ValueError):
    """Initramfs entry refused."""


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str  # "file" | "dir" | "symlink"
    data: bytes = b""
    target: str = ""
    mode: int = 0o644


def _check_path(path: str) -> str:
    if not path or path.startswith("/"):
        raise CpioError(f"entry path must be relative: {path!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise CpioError(f"entry path escapes or is empty: {path!r}")
    return path


def file_entry(path: str, data: bytes, mode: int = 0o644) -> Entry:
    return Entry(path=_check_path(path), kind="file", data=bytes(data), mode=mode)


def dir_entry(path: str, mode: int = 0o755) -> Entry:
    return Entry(path=_check_path(path), kind="dir", mode=mode)


def symlink_entry(path: str, target: str) -> Entry:
    if not target or target.startswith("/"):
        raise CpioError(f"symlink target must be relative: {target!r}")
    return Entry(path=_check_path(path), kind="symlink", target=target)


def _field(value: int) -> bytes:
    return f"{value & 0xFFFFFFFF:08x}".encode("ascii")


def _pad(length: int) -> bytes:
    return b"\x00" * ((4 - (length % 4)) % 4)


def build_cpio(entries: list[Entry]) -> bytes:
    """Pack entries as a newc archive (deterministic, trailered)."""
    ordered = sorted(entries, key=lambda entry: entry.path)
    seen: set[str] = set()
    out = bytearray()
    for entry in ordered:
        if entry.path in seen:
            raise CpioError(f"duplicate entry path: {entry.path!r}")
        seen.add(entry.path)
        if entry.kind == "file":
            file_mode = stat.S_IFREG | entry.mode
            body: bytes = entry.data
            nlink = 1
        elif entry.kind == "dir":
            file_mode = stat.S_IFDIR | entry.mode
            body = b""
            nlink = 2
        elif entry.kind == "symlink":
            file_mode = stat.S_IFLNK | 0o777
            body = entry.target.encode()
            nlink = 1
        else:  # pragma: no cover - constructor-only kinds
            raise CpioError(f"unknown entry kind: {entry.kind!r}")
        name = entry.path.encode() + b"\x00"
        header = (
            b"070701"
            + _field(0)  # ino
            + _field(file_mode)
            + _field(0)  # uid
            + _field(0)  # gid
            + _field(nlink)
            + _field(0)  # mtime: fixed epoch
            + _field(len(body))
            + _field(0)  # devmajor
            + _field(0)  # devminor
            + _field(0)  # rdevmajor
            + _field(0)  # rdevminor
            + _field(len(name))
            + _field(0)  # check
        )
        out += header + name + _pad(len(header) + len(name))
        out += body + _pad(len(body))
    trailer = b"TRAILER!!!\x00"
    header = (
        b"070701"
        + _field(0)
        + _field(0)
        + _field(0)
        + _field(0)
        + _field(1)
        + _field(0)
        + _field(0)
        + _field(0)
        + _field(0)
        + _field(0)
        + _field(0)
        + _field(len(trailer))
        + _field(0)
    )
    out += header + trailer + _pad(len(header) + len(trailer))
    # cpio archives are conventionally padded to a 512-byte boundary.
    out += b"\x00" * ((512 - (len(out) % 512)) % 512)
    return bytes(out)


def build_cpio_gz(entries: list[Entry]) -> bytes:
    """Pack entries and gzip with mtime=0 (deterministic)."""
    return gzip.compress(build_cpio(entries), compresslevel=9, mtime=0)
