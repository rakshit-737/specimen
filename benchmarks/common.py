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


def bootstrap_ci(y: np.ndarray, s: np.ndarray, metric: str, n: int = 1000, seed: int = 0,
                 thr: float = 0.5) -> tuple[float, float]:
    """95 % percentile bootstrap CI of one ``binary_metrics`` field over test rows."""
    from sklearn.metrics import roc_auc_score
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        if len(np.unique(y[i])) < 2:
            continue
        if metric == "roc_auc":
            vals.append(roc_auc_score(y[i], s[i]))
        else:
            vals.append(binary_metrics_fast(y[i], s[i], thr)[metric])
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return round(float(lo), 4), round(float(hi), 4)


def binary_metrics_fast(y: np.ndarray, s: np.ndarray, thr: float = 0.5) -> dict[str, float]:
    pred = s >= thr
    tp = float((pred & (y == 1)).sum())
    fp = float((pred & (y == 0)).sum())
    fn = float((~pred & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"accuracy": float((pred == (y == 1)).mean()), "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0}


def mean_ci(vals: list[float]) -> str:
    """mean +/- 95 % t-interval half-width over seeds/folds."""
    a = np.asarray(vals, dtype=float)
    if len(a) < 2:
        return f"{a.mean():.4f}"
    from scipy import stats
    h = stats.t.ppf(0.975, len(a) - 1) * a.std(ddof=1) / np.sqrt(len(a))
    return f"{a.mean():.4f} +/- {h:.4f}"


def mean_ci_nb(vals: list[float], n_train: int, n_test: int) -> str:
    """mean +/- 95 % Nadeau-Bengio corrected resampled-t half-width.

    Repeated splits/folds share training data, so the naive t-interval is too
    narrow; the corrected variance is ``s^2 * (1/J + n_test/n_train)``."""
    a = np.asarray(vals, dtype=float)
    if len(a) < 2:
        return f"{a.mean():.4f}"
    from scipy import stats
    var = a.var(ddof=1) * (1 / len(a) + n_test / n_train)
    h = stats.t.ppf(0.975, len(a) - 1) * np.sqrt(var)
    return f"{a.mean():.4f} +/- {h:.4f}"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95 % interval for a binomial proportion."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(float(max(0.0, c - h)), 6), round(float(min(1.0, c + h)), 6)
