"""Build the compact negative corpus shipped as package data.

Streams the Avast-CTU token cache (``$SPECIMEN_DATA/cache/avast_tokens.jsonl.gz``),
draws a fixed stratified sample of *train-split* runs per family and writes
``specimen/data/negatives.json.gz``:

* ``lines``: per Sigma category, every distinct event line of the sampled
  runs with the families it was seen in (so the pipeline can leave out the
  predicted family's own behaviour);
* ``imports``: per-family import prevalence for ranking YARA import rules.

Only test-split-free data goes in, so benchmark numbers on the test split
are not contaminated. Stdlib only; peak memory well under 1 GB.

    python scripts/build_negative_corpus.py --per-family 200 --seed 0
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from specimen.datasets import data_root  # noqa: E402
from specimen.detect import event_line  # noqa: E402

OUT = ROOT / "specimen" / "data" / "negatives.json.gz"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--per-family", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args()
    cache = data_root() / "cache" / "avast_tokens.jsonl.gz"
    rng = random.Random(a.seed)
    # reservoir sample per family (stream; never hold the whole cache)
    res: dict[str, list] = defaultdict(list)
    seen: dict[str, int] = defaultdict(int)
    with gzip.open(cache, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["split"] != "train" or not r["events"]:
                continue
            fam = r["family"]
            seen[fam] += 1
            item = (r["events"], [t for t in r["static"] if t.startswith("imp:")])
            if len(res[fam]) < a.per_family:
                res[fam].append(item)
            else:
                j = rng.randrange(seen[fam])
                if j < a.per_family:
                    res[fam][j] = item
    fams = sorted(res)
    lines: dict[str, dict[str, set[int]]] = defaultdict(dict)
    imports: dict[str, dict[str, float]] = {}
    for fi, fam in enumerate(fams):
        cnt: dict[str, int] = defaultdict(int)
        for events, imps in res[fam]:
            for e in events:
                r = event_line(e[0], e[1], e[2] if len(e) > 2 else "")
                if r and r[1]:
                    lines[r[0]].setdefault(r[1].replace("\n", " "), set()).add(fi)
            for t in set(imps):
                cnt[t] += 1
        n = len(res[fam])
        imports[fam] = {t: round(c / n, 4) for t, c in sorted(cnt.items()) if c >= 2}
    doc = {
        "meta": {"source": "Avast-CTU CAPEv2 reduced reports, split=train (Bosansky et al. 2022)",
                 "per_family": {f: len(res[f]) for f in fams}, "seed": a.seed,
                 "families": fams, "note": "event lines of sampled train runs; never used for test-split scoring"},
        "lines": {c: [[ln, sorted(fs)] for ln, fs in sorted(v.items())] for c, v in sorted(lines.items())},
        "imports": imports,
    }
    blob = gzip.compress(json.dumps(doc, separators=(",", ":"), sort_keys=True).encode(), mtime=0)
    a.out.write_bytes(blob)
    print(f"{sum(len(v) for v in lines.values())} lines, {len(fams)} families -> {a.out} "
          f"({len(blob) / 1024:.0f} KiB, sha256 {hashlib.sha256(blob).hexdigest()[:16]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
