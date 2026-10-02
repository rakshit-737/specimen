import hashlib
from pathlib import Path


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: str | Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


#: Largest report / trace file read into memory (override with SPECIMEN_MAX_INPUT_MB).
MAX_INPUT_MB = 512


def read_capped(p: str | Path) -> bytes:
    """Read an input report or trace, refusing files above the size cap.

    :param p: path to a JSON/XML report or trace.
    :returns: the file's bytes.
    :raises ValueError: if the file is larger than ``SPECIMEN_MAX_INPUT_MB`` (default 512 MB).
    """
    import os
    cap = float(os.environ.get("SPECIMEN_MAX_INPUT_MB", MAX_INPUT_MB)) * 1024 * 1024
    size = Path(p).stat().st_size
    if size > cap:
        raise ValueError(f"{p}: {size} bytes exceeds the input cap of {int(cap)} bytes (SPECIMEN_MAX_INPUT_MB)")
    return Path(p).read_bytes()
