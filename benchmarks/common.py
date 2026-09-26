"""Shared helpers for the benchmark scripts."""
from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
FIGURES = ROOT / "docs" / "figures"
sys.path.insert(0, str(ROOT))


def tpr_at_fpr(y: np.ndarray, s: np.ndarray, fpr_target: float) -> float:
    fpr, tpr, _ = roc_curve(y, s)
    ok = fpr <= fpr_target
    return float(tpr[ok].max()) if ok.any() else 0.0


def binary_metrics(y: np.ndarray, s: np.ndarray, thr: float = 0.5) -> dict[str, float]:
    pred = s >= thr
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "roc_auc": round(float(roc_auc_score(y, s)), 5),
        "tpr@0.1%fpr": round(tpr_at_fpr(y, s, 1e-3), 4),
        "tpr@1%fpr": round(tpr_at_fpr(y, s, 1e-2), 4),
        "accuracy": round(float((pred == (y == 1)).mean()), 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
    }


def write_result(name: str, payload: dict[str, Any]) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    payload = {"benchmark": name, "generated": time.strftime("%Y-%m-%d"), "python": platform.python_version(),
               **payload}
    p = RESULTS / f"{name}.json"
    p.write_text(json.dumps(payload, indent=2, default=float) + "\n")
    print(f"wrote {p}")
    return p


def md_table(rows: list[dict[str, Any]], cols: list[str]) -> str:
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(out)
