"""Minimal durable job queue for batches of reports (stdlib only).

Jobs are recorded in an append-only ``jobs.jsonl`` ledger (queued ->
done | failed). Re-running the same batch skips jobs already ``done``, so an
interrupted batch resumes. Work runs in a process pool; one bad report
fails its job, never the batch. A Redis/RQ backend can replace the pool
without changing the ledger format (see docs/adr/0004-job-queue.md).
"""
from __future__ import annotations

import json
import multiprocessing
import time
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .hashing import sha256_file


def _job(path: str, out: str) -> dict[str, Any]:
    from .pipeline import run_report
    from .report import render_markdown
    t0 = time.time()
    rep = run_report(path)
    stem = Path(path).stem
    o = Path(out)
    (o / f"{stem}.json").write_text(json.dumps(rep, indent=2, default=str))
    (o / f"{stem}.md").write_text(render_markdown(rep), encoding="utf-8")
    b = rep.get("behavior") or {}
    return {"verdict": rep["verdict"]["label"], "confidence": rep["verdict"]["confidence"],
            "family": b.get("family"), "techniques": len(rep["techniques"]),
            "sigma": len(rep["detections"]["sigma"]), "yara": bool(rep["detections"]["yara"]),
            "seconds": round(time.time() - t0, 3)}


def ledger_state(ledger: Path) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # torn final line after a crash
            state[rec["job_id"]] = rec
    return state


def run_batch(inputs: Iterable[Path], out: Path, workers: int = 2) -> list[dict[str, Any]]:
    out.mkdir(parents=True, exist_ok=True)
    ledger = out / "jobs.jsonl"
    state = ledger_state(ledger)
    todo = []
    for p in sorted(inputs):
        jid = sha256_file(p)[:16]
        if state.get(jid, {}).get("status") == "done":
            continue
        todo.append((jid, p))
    results = []
    with open(ledger, "a", encoding="utf-8") as lg:
        def log(rec: dict[str, Any]) -> None:
            lg.write(json.dumps(rec) + "\n")
            lg.flush()
        for jid, p in todo:
            log({"job_id": jid, "path": str(p), "status": "queued", "ts": time.time()})
        with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("spawn")) as ex:
            futs = {ex.submit(_job, str(p), str(out)): (jid, p) for jid, p in todo}
            for fut in as_completed(futs):
                jid, p = futs[fut]
                try:
                    rec = {"job_id": jid, "path": str(p), "status": "done", "ts": time.time(), **fut.result()}
                except Exception as e:  # noqa: BLE001 - isolate per-job failures
                    rec = {"job_id": jid, "path": str(p), "status": "failed", "ts": time.time(),
                           "error": f"{type(e).__name__}: {e}"[:300]}
                log(rec)
                results.append(rec)
    return results
