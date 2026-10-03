"""Loaders for the public datasets used in the benchmarks.

All readers are *streaming* and *truncation tolerant*: they read archives
front-to-back without the zip central directory / full tar index, so a
partially downloaded archive yields every complete record before the cut.
Nothing here ever touches a binary - only reports, features and labels.
"""
from __future__ import annotations

import bz2
import csv
import io
import json
import os
import struct
import tarfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DATA_ENV = "SPECIMEN_DATA"


def data_root() -> Path:
    """Dataset root: ``$SPECIMEN_DATA`` if set, else ``./data`` (always outside the repository)."""
    return Path(os.environ.get(DATA_ENV, "data"))


# --------------------------------------------------------------------------
# streaming zip reader (handles data descriptors and nested zips)
# --------------------------------------------------------------------------

class _Buf:
    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._it = chunks
        self._buf = bytearray()

    def read(self, n: int) -> bytes:
        """Return up to ``n`` bytes, pulling chunks from the underlying iterator as needed."""
        while len(self._buf) < n:
            try:
                self._buf += next(self._it)
            except StopIteration:
                break
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def unread(self, b: bytes) -> None:
        """Push bytes back so the next :meth:`read` returns them first."""
        self._buf[:0] = b


def _file_chunks(path: Path, size: int = 1 << 20) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while b := f.read(size):
            yield b


class ZipTruncated(Exception):
    """Raised when a streamed archive ends mid-record (partial download)."""


def _entries(buf: _Buf) -> Iterator[tuple[str, Iterator[bytes]]]:
    while True:
        if buf.read(4) != b"PK\x03\x04":
            return  # central directory reached, or truncated/zero-filled tail
        hdr = buf.read(26)
        if len(hdr) < 26:
            return
        _ver, flag, meth, _t, _d, _crc, csize, _usize, nlen, elen = struct.unpack("<HHHHHIIIHH", hdr)
        name = buf.read(nlen).decode("utf-8", "replace")
        buf.read(elen)
        descriptor = bool(flag & 8)

        def payload() -> Iterator[bytes]:
            if meth == 0 and not descriptor:
                left = csize
                while left:
                    b = buf.read(min(left, 1 << 20))
                    if not b:
                        raise ZipTruncated
                    left -= len(b)
                    yield b
                return
            if meth != 8:
                raise ZipTruncated  # unsupported method: cannot resync, stop
            z = zlib.decompressobj(-15)
            left = csize if not descriptor else None
            while not z.eof:
                b = buf.read(1 << 16 if left is None else min(left, 1 << 16))
                if not b:
                    raise ZipTruncated
                if left is not None:
                    left -= len(b)
                try:
                    out = z.decompress(b)
                except zlib.error as e:
                    raise ZipTruncated from e
                if z.eof and z.unused_data:
                    buf.unread(z.unused_data)
                if out:
                    yield out

        gen = payload()
        try:
            yield name, gen
            for _ in gen:  # drain whatever the consumer did not read
                pass
        except ZipTruncated:
            return
        if descriptor:
            d = buf.read(4)
            buf.read(12 if d == b"PK\x07\x08" else 8)


def iter_zip(path: Path) -> Iterator[tuple[str, Iterator[bytes]]]:
    """Yield ``(name, chunk_iterator)`` for each member; nested ``*.zip``
    members are expanded recursively as ``outer/inner`` names. Consumers
    reading a chunk iterator may see ``ZipTruncated`` on a partial archive."""
    try:
        yield from _iter_zip_buf(_Buf(_file_chunks(path)), "")
    except ZipTruncated:
        return


def _iter_zip_buf(buf: _Buf, prefix: str) -> Iterator[tuple[str, Iterator[bytes]]]:
    for name, chunks in _entries(buf):
        if name.startswith("__MACOSX/") or name.endswith("/"):
            continue
        if name.lower().endswith(".zip"):
            yield from _iter_zip_buf(_Buf(chunks), prefix + name + "/")
        else:
            yield prefix + name, chunks


# --------------------------------------------------------------------------
# Avast-CTU Public CAPEv2 dataset (reduced reports)
# --------------------------------------------------------------------------

AVAST_ZIP = "avast_cape/Public_Avast_CTU_CAPEv2_Dataset_Small.zip"
AVAST_SPLIT_DATE = "2019-08-01"  # train/test split used by Bosansky et al. 2022


@dataclass(frozen=True)
class AvastLabel:
    """One row of the Avast-CTU label file: hash, family, malware type and first-seen date."""
    sha256: str
    family: str
    mtype: str
    date: str

    @property
    def split(self) -> str:
        """``train`` before the authors' split date (2019-08-01), else ``test``."""
        return "train" if self.date < AVAST_SPLIT_DATE else "test"


def parse_avast_labels(text: str) -> dict[str, AvastLabel]:
    """Parse the Avast-CTU label CSV into ``{sha256: AvastLabel}``."""
    out = {}
    for row in csv.DictReader(io.StringIO(text)):
        out[row["sha256"]] = AvastLabel(row["sha256"], row["classification_family"],
                                        row["classification_type"], row["date"])
    return out


def iter_avast(path: Path | None = None, limit: int | None = None, parse: bool = True
               ) -> Iterator[tuple[AvastLabel, Any]]:
    """Stream ``(label, reduced_report)`` pairs from the (possibly partial) archive.

    With ``parse=False`` the report is yielded as raw JSON bytes (lets the
    caller parse in worker processes)."""
    path = path or data_root() / AVAST_ZIP
    labels: dict[str, AvastLabel] = {}
    n = 0
    for name, chunks in iter_zip(path):
        try:
            raw = b"".join(chunks)
        except ZipTruncated:
            return
        base = name.rsplit("/", 1)[-1]
        if base == "public_labels.csv":
            labels = parse_avast_labels(raw.decode("utf-8"))
            continue
        if not base.endswith(".json"):
            continue
        sha = base[:-5]
        lab = labels.get(sha)
        if lab is None:
            continue
        if not parse:
            yield lab, raw
        else:
            try:
                rep = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            yield lab, rep
        n += 1
        if limit and n >= limit:
            return


# --------------------------------------------------------------------------
# EMBER 2018 v2 raw features (JSON lines inside tar.bz2)
# --------------------------------------------------------------------------

EMBER_TAR = "ember/ember_dataset_2018_2.tar.bz2"


def iter_ember(path: Path | None = None, limit: int | None = None,
               labelled_only: bool = True) -> Iterator[dict[str, Any]]:
    """Stream raw EMBER feature dicts from a (possibly truncated) tar.bz2."""
    path = path or data_root() / EMBER_TAR
    n = 0
    try:
        with bz2.open(path, "rb") as bz, tarfile.open(fileobj=bz, mode="r|") as tf:
            for m in tf:
                if not m.isfile() or not m.name.endswith(".jsonl"):
                    continue
                f = tf.extractfile(m)
                if f is None:
                    continue
                for line in f:
                    try:
                        row = json.loads(line)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return
                    if labelled_only and row.get("label") not in (0, 1):
                        continue
                    row["_member"] = m.name
                    yield row
                    n += 1
                    if limit and n >= limit:
                        return
    except (EOFError, OSError, tarfile.TarError):
        return  # truncated prefix download: stop at the last complete record


# --------------------------------------------------------------------------
# MalbehavD-V1 API-call sequences
# --------------------------------------------------------------------------

MALBEHAVD_CSV = "malbehavd/MalBehavD-V1-dataset.csv"


def iter_malbehavd(path: Path | None = None) -> Iterator[tuple[str, int, list[str]]]:
    """Yield ``(sha256, label, api_calls)`` rows of the MalbehavD-V1 CSV (label 1 = malicious)."""
    path = path or data_root() / MALBEHAVD_CSV
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.reader(f)
        next(r)
        for row in r:
            yield row[0], int(row[1]), [a for a in row[2:] if a]
