"""Fetch the trained model files (family model, EMBER gate) and verify their pinned SHA-256s.

    python scripts/fetch_models.py [--dest models]

The models are too large for git. ``scripts/model_assets.json`` pins the
SHA-256 of every file and names where it can come from, in order:

1. the release named in the lock (``release``), if any;
2. the latest GitHub release (anonymous HTTPS download);
3. the ``bench`` workflow artefacts that produced the files (``bench_runs``;
   needs the ``gh`` CLI with a token that can read Actions artefacts).

A source is used only if *every* file from it matches the lock; otherwise the
script tries the next source and finally exits non-zero. ``docs.yml`` (demo
pages) and ``release.yml`` (release assets) both call it, so neither can
silently fall back to a different or missing model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "scripts" / "model_assets.json"
REPO = "rakshit-737/specimen"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def from_release(tag: str | None, names: list[str], tmp: Path) -> bool:
    base = (f"https://github.com/{REPO}/releases/latest/download/" if tag is None
            else f"https://github.com/{REPO}/releases/download/{tag}/")
    for n in names:
        try:
            with urllib.request.urlopen(base + n, timeout=120) as r, open(tmp / n, "wb") as f:  # noqa: S310 - fixed https URL
                shutil.copyfileobj(r, f)
        except OSError as e:
            print(f"  {n}: {e}")
            return False
    return True


def from_run(run_id: int, artifact: str, names: list[str], tmp: Path) -> bool:
    if not shutil.which("gh"):
        print("  gh CLI not found")
        return False
    out = tmp / "artifact" / f"{run_id}-{artifact}"
    r = subprocess.run(["gh", "run", "download", str(run_id), "-R", REPO, "-n", artifact, "-D", str(out)],
                       capture_output=True, text=True)
    if r.returncode:
        print(f"  gh run download failed: {r.stderr.strip()[:300]}")
        return False
    for n in names:
        hits = list(out.rglob(n))
        if not hits:
            print(f"  {n} not in artefact {artifact} of run {run_id}")
            return False
        shutil.copyfile(hits[0], tmp / n)
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", type=Path, default=ROOT / "models")
    ap.add_argument("--only", default="", help="comma-separated prefixes, e.g. family_ (default: all files)")
    a = ap.parse_args(argv)
    lock = json.loads(LOCK.read_text())
    files: dict[str, str] = {n: v["sha256"] for n, v in lock["files"].items()
                             if not a.only or n.startswith(tuple(a.only.split(",")))}
    groups: dict[tuple[int, str], list[str]] = {}
    for n in files:
        src = lock["files"][n].get("bench_run")
        if src:
            groups.setdefault((int(src["run_id"]), src["artifact"]), []).append(n)
    sources = ([("release " + lock["release"], lambda t: from_release(lock["release"], list(files), t))]
               if lock.get("release") else [])
    sources.append(("latest release", lambda t: from_release(None, list(files), t)))
    if groups:
        def runs(t: Path) -> bool:
            return all(from_run(rid, art, names, t) for (rid, art), names in groups.items())
        sources.append(("bench run artefacts " + ", ".join(str(r) for r, _ in groups), runs))
    a.dest.mkdir(parents=True, exist_ok=True)
    for label, fetch in sources:
        print(f"trying {label}")
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            if not fetch(t):
                continue
            bad = [n for n, h in files.items() if sha256(t / n) != h]
            if bad:
                print(f"  SHA-256 mismatch for {', '.join(bad)}; not used")
                continue
            for n in files:
                shutil.copyfile(t / n, a.dest / n)
            print(f"fetched {len(files)} model files from {label} into {a.dest} (SHA-256 verified)")
            for n, h in files.items():
                print(f"  {h}  {n}")
            return 0
    print("ERROR: no source provided model files matching scripts/model_assets.json", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
