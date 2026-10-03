"""Avast-CTU CAPEv2 corpus -> compact token cache.

Parsing ~49k JSON reports takes a few minutes, so the benchmarks run on a
gzip JSON-lines cache (one record per report) written next to the data.
Each record keeps only what the models and the rule synthesizer need.
"""
from __future__ import annotations

import gzip
import json
import multiprocessing as mp
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..adapters.cape import CapeFormatError, cape_to_trace, static_pe
from ..datasets import data_root, iter_avast
from ..tokens import behavior_tokens, static_tokens

RULE_EVENT_TYPES = ("process_create", "registry_set", "file_write", "service_create")
MAX_RULE_EVENTS = 400
CACHE = "cache/avast_tokens.jsonl.gz"


def report_record(report: dict[str, Any], run_id: str) -> dict[str, Any] | None:
    """Compact cache record of one Avast-CTU report: behaviour and static tokens and the host-action rows the rule synthesizer needs."""
    try:
        trace = cape_to_trace(report, run_id=run_id)
    except CapeFormatError:
        trace = None
    pe = static_pe(report)
    ev = []
    if trace is not None:
        for e in trace.events:
            if e.type in RULE_EVENT_TYPES and len(ev) < MAX_RULE_EVENTS:
                ev.append([e.type, e.target or "", e.cmdline or ""])
    return {
        "beh": behavior_tokens(trace) if trace else [],
        "static": static_tokens(pe),
        "events": ev,
        "imphash": pe.get("imphash") or "",
        "n_events": len(trace.events) if trace else 0,
    }


def _work(item: tuple[Any, bytes]) -> str | None:
    lab, raw = item
    try:
        rep = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    rec = report_record(rep, lab.sha256)
    if rec is None:
        return None
    rec.update(sha256=lab.sha256, family=lab.family, mtype=lab.mtype, date=lab.date, split=lab.split)
    return json.dumps(rec, separators=(",", ":"))


def build_cache(zip_path: Path | None = None, out: Path | None = None, limit: int | None = None,
                workers: int | None = None) -> Path:
    """Parse every report (in ``workers`` processes) into the token cache."""
    out = out or data_root() / CACHE
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    t0 = time.time()
    n = 0
    workers = workers or max(1, (os.cpu_count() or 2) // 2)
    with gzip.open(tmp, "wt", encoding="utf-8") as f, mp.Pool(workers) as pool:
        for line in pool.imap(_work, iter_avast(zip_path, limit=limit, parse=False), chunksize=8):
            if line is None:
                continue
            f.write(line + "\n")
            n += 1
            if n % 5000 == 0:
                print(f"  {n} reports  {time.time() - t0:.0f}s", flush=True)
    tmp.replace(out)
    print(f"cached {n} reports -> {out} ({time.time() - t0:.0f}s)")
    return out


def load_cache(path: Path | None = None) -> Iterator[dict[str, Any]]:
    """Stream the Avast-CTU token cache (one dict per report)."""
    path = path or data_root() / CACHE
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)
