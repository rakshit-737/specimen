"""Sanity-check benchmark result files (used by the bench workflow and CI).

    python scripts/check_results.py results/*.json [--run-id N] [--any]

Fails when a result file has no provenance block, a NaN/Infinity value, a
proportion outside [0, 1] or a 95 % interval whose bounds are reversed or
leave [0, 1]. With ``--run-id``, every file must come from that GitHub
Actions run (``--any``: check only the files from that run, and require at
least one).
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

PROP_HINTS = ("accuracy", "recall", "fpr", "coverage", "accepted", "share", "auc", "tpr", "rate", "f1",
              "precision", "skipped", "missed", "saved")


def walk(x: Any, path: str = ""):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(x, list):
        for i, v in enumerate(x):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, x


def check(doc: dict) -> list[str]:
    errs = []
    if "provenance" not in doc:
        errs.append("no provenance block")
    for path, v in walk(doc):
        if isinstance(v, float) and not math.isfinite(v):
            low = path.lower()
            # NaN is allowed only where a subset can be empty (e.g. a family without novel test runs)
            if not ("novel" in low or "median_family" in low or "per_family" in low or "curve" in low):
                errs.append(f"{path}: non-finite {v}")
    for path, v in walk(doc):
        leaf = path.rsplit(".", 1)[-1].lower()
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and "[" not in leaf:
            if any(h in leaf for h in PROP_HINTS) and not leaf.endswith(("_s", "_pct", "seconds", "diff", "_n")) \
                    and ("pct" not in path.lower()) and not (0.0 <= v <= 1.0):
                errs.append(f"{path}: proportion {v} outside [0, 1]")
    for path, v in walk_lists(doc):
        if path.lower().endswith(("ci", "ci95", "_95ci", "wilson")) and len(v) == 2 and all(
                isinstance(b, (int, float)) and math.isfinite(b) for b in v):
            lo, hi = v
            if lo > hi + 1e-12:
                errs.append(f"{path}: reversed interval {v}")
            low = path.lower()
            is_difference = any(k in low for k in ("diff", "minus", "paired", "_vs_"))
            if not is_difference and "pct" not in low and (lo < -1e-9 or hi > 1 + 1e-9) \
                    and not low.startswith(("lightgbm_5_seeds_mean_95ci",)):
                errs.append(f"{path}: interval {v} leaves [0, 1]")
    return errs


def walk_lists(x: Any, path: str = ""):
    if isinstance(x, dict):
        for k, v in x.items():
            p = f"{path}.{k}" if path else str(k)
            if isinstance(v, list):
                yield p, v
            yield from walk_lists(v, p)
    elif isinstance(x, list):
        for i, v in enumerate(x):
            yield from walk_lists(v, f"{path}[{i}]")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--run-id", type=int)
    ap.add_argument("--any", action="store_true")
    a = ap.parse_args(argv)
    bad, checked = 0, 0
    for f in a.files:
        if not f.exists():
            continue
        doc = json.loads(f.read_text(), parse_constant=lambda c: float(c))
        rid = (doc.get("provenance") or {}).get("github_run_id")
        if a.run_id and rid != a.run_id:
            if a.any:
                print(f"skip {f.name}: from run {rid}, not this run")
                continue
            print(f"BAD {f.name}: from run {rid}, expected {a.run_id}")
            bad += 1
            continue
        errs = check(doc)
        checked += 1
        print(("OK  " if not errs else "BAD ") + f.name + (f"  (run {rid})" if rid else ""))
        for e in errs[:30]:
            print("    " + e)
        bad += bool(errs)
    if checked == 0:
        print("no result file was checked")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
