"""Resumable, parallel HTTP range downloader with SHA-256 verification.

Standard library only. Progress is tracked in ``<dest>.chunks.json`` so an
interrupted download resumes where it stopped. ``max_bytes`` fetches only a
prefix of the file (used for EMBER, whose tar.bz2 can be stream-decoded).
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

UA = {"User-Agent": "specimen-dataset-fetcher/0.2 (+https://github.com/rakshit-737/specimen-malware-analysis)"}
CHUNK = 4 * 1024 * 1024


def remote_size(url: str, retries: int = 20) -> int:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={**UA, "Range": "bytes=0-0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                cr = r.headers.get("Content-Range", "")
                if "/" in cr:
                    return int(cr.rsplit("/", 1)[1])
                return int(r.headers.get("Content-Length", "0"))
        except Exception as e:  # noqa: BLE001
            if attempt == retries - 1:
                raise
            print(f"  size probe retry: {e}", file=sys.stderr)
            time.sleep(min(2 * (attempt + 1), 30))
    raise RuntimeError("unreachable")


def _fetch(url: str, start: int, end: int, retries: int = 30) -> bytes:
    delay = 2.0
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={**UA, "Range": f"bytes={start}-{end}"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            if len(data) == end - start + 1:
                return data
            raise OSError(f"short read {len(data)} != {end - start + 1}")
        except Exception as e:  # noqa: BLE001 - network errors of any kind are retried
            if attempt == retries - 1:
                raise
            print(f"  retry {start}-{end}: {e}", file=sys.stderr)
            time.sleep(delay)
            delay = min(delay * 1.5, 60)
    raise RuntimeError("unreachable")


def download(url: str, dest: Path, *, max_bytes: int | None = None, workers: int = 6,
             expected_sha256: str | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    total = remote_size(url)
    size = min(total, max_bytes) if max_bytes else total
    state_path = dest.with_name(dest.name + ".chunks.json")
    done: set[int] = set()
    if state_path.exists() and dest.exists():
        st = json.loads(state_path.read_text())
        if st.get("size") == size and st.get("url") == url:
            if st.get("complete") and dest.stat().st_size == size:
                print(f"{dest.name}: already complete ({size / 1e6:.1f} MB)")
                return _verify(dest, expected_sha256)
            done = set(st.get("done", []))
    if not dest.exists() or dest.stat().st_size != size:
        with open(dest, "wb") as f:
            f.truncate(size)
        done = set()
    chunks = [(i, i * CHUNK, min((i + 1) * CHUNK, size) - 1) for i in range((size + CHUNK - 1) // CHUNK)]
    todo = [c for c in chunks if c[0] not in done]
    lock = threading.Lock()
    t0 = time.time()
    got = 0
    print(f"{dest.name}: {size / 1e6:.1f} MB ({len(todo)}/{len(chunks)} chunks to fetch)")
    with open(dest, "r+b") as f, ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(_fetch, url, s, e): (i, s, e) for i, s, e in todo}
        for fut in as_completed(futs):
            i, s, e = futs[fut]
            data = fut.result()
            with lock:
                f.seek(s)
                f.write(data)
                f.flush()
                done.add(i)
                got += len(data)
                state_path.write_text(json.dumps({"url": url, "size": size, "done": sorted(done)}))
                rate = got / max(time.time() - t0, 1e-6) / 1e3
                print(f"  {len(done)}/{len(chunks)} chunks  {rate:.0f} kB/s", flush=True)
    state_path.write_text(json.dumps({"url": url, "size": size, "complete": True}))
    return _verify(dest, expected_sha256)


def _verify(dest: Path, expected_sha256: str | None) -> Path:
    if expected_sha256:
        h = sha256_file(dest)
        if h != expected_sha256:
            raise SystemExit(f"SHA-256 mismatch for {dest}: {h} != {expected_sha256}")
        print(f"  sha256 OK {h}")
    return dest


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
