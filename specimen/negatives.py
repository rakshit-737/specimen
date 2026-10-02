"""Packaged negative corpus for the Sigma/YARA specificity check.

``specimen/data/negatives.json.gz`` holds the event lines (and import
prevalence) of a fixed stratified sample of Avast-CTU *train-split* runs of
nine families, built by ``scripts/build_negative_corpus.py``. The report
path checks every candidate rule against it, so the shipped synthesizer
uses the same kind of real negatives the rule benchmark measures, not
only the small synthetic benign corpus.
"""
from __future__ import annotations

import gzip
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

FILE = Path(__file__).resolve().parent / "data" / "negatives.json.gz"


@lru_cache(maxsize=1)
def _doc() -> dict[str, Any] | None:
    if not FILE.exists():
        return None
    return json.loads(gzip.decompress(FILE.read_bytes()))


def meta() -> dict[str, Any]:
    """Corpus metadata (source, families, runs per family); empty if absent."""
    d = _doc()
    return dict(d["meta"]) if d else {}


@lru_cache(maxsize=16)
def negative_blob(exclude_family: str | None = None) -> dict[str, str] | None:
    """One per-category blob of every negative line, leaving out lines seen
    only in ``exclude_family`` (the sample's own predicted family).

    :returns: blob in the format of :func:`specimen.detect.blobs`, or ``None``
        when the corpus is not installed.
    """
    d = _doc()
    if d is None:
        return None
    fams = d["meta"]["families"]
    ex = fams.index(exclude_family) if exclude_family in fams else -1
    return {c: "\n".join(ln for ln, fs in rows if fs != [ex]) for c, rows in d["lines"].items()}


@lru_cache(maxsize=16)
def import_prevalence(exclude_family: str | None = None) -> dict[str, float]:
    """Max per-family prevalence of each import token over the other families."""
    d = _doc()
    out: dict[str, float] = {}
    for fam, table in (d or {}).get("imports", {}).items():
        if fam == exclude_family:
            continue
        for t, p in table.items():
            if p > out.get(t, 0.0):
                out[t] = p
    return out
