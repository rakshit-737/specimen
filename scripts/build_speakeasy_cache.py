"""Benign Quo Vadis Speakeasy reports -> compact rule-matching cache (run inside GitHub Actions).

    python scripts/build_speakeasy_cache.py --dest "$SPECIMEN_DATA" [--max 0] [--keep-raw]

Downloads only the *benign* folders (``report_clean`` and
``report_windows_syswow64`` of the train and test sets: 32,673 Speakeasy JSON
reports, about 1.6 GB, no binaries) of the Hugging Face dataset
``dtrizna/quovadis-speakeasy`` (Trizna 2022, Apache-2.0) at a pinned
revision, converts each report with :mod:`specimen.adapters.speakeasy` and
writes ``<dest>/cache/speakeasy_benign.jsonl.gz`` (one record per report: the
host-action event rows the Sigma matcher uses) plus
``speakeasy_benign.meta.json`` (revision, counts, event-type histogram,
SHA-256 of the cache). The raw reports are deleted afterwards unless
``--keep-raw``.

More than 1 GB: run it in the ``bench`` workflow (shared-machine rule), not on
a laptop. Needs ``pip install huggingface_hub``.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from specimen.adapters.speakeasy import speakeasy_to_trace  # noqa: E402

REPO = "dtrizna/quovadis-speakeasy"
REVISION = "fc2e98fac0b4d43a5557ccab70c877af6cce9f4d"  # pinned dataset commit
FOLDERS = ["report_clean", "report_windows_syswow64"]
SPLITS = ["windows_emulation_trainset", "windows_emulation_testset"]
RULE_TYPES = ("process_create", "registry_set", "file_write")
MAX_EVENTS = 2000


def download(raw: Path, attempts: int = 8) -> None:
    from huggingface_hub import snapshot_download
    patterns = [f"{s}/{f}/*" for s in SPLITS for f in FOLDERS]
    for i in range(attempts):
        try:
            snapshot_download(repo_id=REPO, repo_type="dataset", revision=REVISION, allow_patterns=patterns,
                              local_dir=raw, max_workers=8)
            return
        except Exception as e:  # noqa: BLE001 - rate limits / transient network errors: resume after a pause
            wait = min(600, 60 * (i + 1))
            print(f"download attempt {i + 1} failed ({type(e).__name__}: {str(e)[:200]}); retrying in {wait}s",
                  flush=True)
            time.sleep(wait)
    raise SystemExit("could not download the Speakeasy reports")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", type=Path, default=Path(os.environ.get("SPECIMEN_DATA", "data")))
    ap.add_argument("--max", type=int, default=0, help="convert at most N reports (0 = all)")
    ap.add_argument("--keep-raw", action="store_true")
    ap.add_argument("--skip-download", action="store_true", help="convert reports already under <dest>/speakeasy")
    a = ap.parse_args(argv)
    raw = a.dest / "speakeasy"
    t0 = time.time()
    if not a.skip_download:
        download(raw)
    print(f"download done in {time.time() - t0:.0f}s", flush=True)
    files = sorted(p for s in SPLITS for f in FOLDERS for p in (raw / s / f).glob("*.json"))
    if a.max:
        files = files[:a.max]
    out = a.dest / "cache" / "speakeasy_benign.jsonl.gz"
    out.parent.mkdir(parents=True, exist_ok=True)
    types: Counter = Counter()
    access: Counter = Counter()
    failed = 0
    per_folder: Counter = Counter()
    with gzip.open(out, "wt", encoding="utf-8", compresslevel=6) as fo:
        for i, p in enumerate(files):
            rel = p.relative_to(raw).as_posix()
            try:
                data = p.read_bytes()
                trace = speakeasy_to_trace(data, run_id=p.stem)
            except (ValueError, OSError) as e:
                failed += 1
                print(f"  skip {rel}: {e}", flush=True)
                continue
            types.update(e.type for e in trace.events)
            access.update(str(e.extra.get("speakeasy_event")) for e in trace.events if e.extra.get("speakeasy_event"))
            per_folder[rel.split("/")[0] + "/" + rel.split("/")[1]] += 1
            ev = [[e.type, e.target or "", e.cmdline or ""] for e in trace.events if e.type in RULE_TYPES][:MAX_EVENTS]
            fo.write(json.dumps({"file": rel, "split": "train" if "trainset" in rel else "test",
                                 "folder": rel.split("/")[1], "events": ev, "n_events": len(trace.events)},
                                separators=(",", ":")) + "\n")
            if (i + 1) % 5000 == 0:
                print(f"  {i + 1}/{len(files)} converted ({time.time() - t0:.0f}s)", flush=True)
    sha = hashlib.sha256(out.read_bytes()).hexdigest()
    meta = {"repo": REPO, "revision": REVISION, "folders": FOLDERS, "splits": SPLITS,
            "reports": sum(per_folder.values()), "failed": failed, "per_folder": dict(sorted(per_folder.items())),
            "event_types": dict(types.most_common()), "speakeasy_access_events": dict(access.most_common()),
            "cache_sha256": sha, "licence": "Apache-2.0",
            "citation": "Trizna D. Quo Vadis: Hybrid Machine Learning Meta-Model Based on Contextual and "
                        "Behavioral Malware Representations. AISec 2022, doi:10.1145/3560830.3563726"}
    out.with_suffix("").with_suffix(".meta.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps(meta, indent=2))
    if not a.keep_raw:
        shutil.rmtree(raw, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
