"""Shared helpers for the benchmark scripts."""
from __future__ import annotations

import json
import os
import platform
import subprocess
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
T_START = time.time()


def require_data(*rel: str) -> Path:
    """Dataset root (``$SPECIMEN_DATA``) after checking that ``rel`` paths exist under it.

    Exits with a one-line hint instead of a traceback when the data is missing."""
    from specimen.datasets import data_root
    root = data_root()
    missing = [r for r in rel if not (root / r).exists()]
    if missing:
        sys.exit(f"data not found under {root}: {', '.join(missing)}. Run: python scripts/download_data.py "
                 f"--dest \"$SPECIMEN_DATA\" (see docs/reproduce.md)")
    return root


def provenance() -> dict[str, Any]:
    """Where and from which commit a result was produced (GitHub Actions run or a local run)."""
    sha = os.environ.get("GITHUB_SHA")
    if not sha:
        try:
            sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                                 timeout=10).stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            sha = None
    run_id = os.environ.get("GITHUB_RUN_ID")
    return {"source": "github-actions" if run_id else "local",
            "github_run_id": int(run_id) if run_id else None,
            "github_run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")) if run_id else None,
            "job": os.environ.get("GITHUB_JOB"),
            "commit": sha,
            "command": " ".join([Path(sys.argv[0]).name, *sys.argv[1:]]) if sys.argv else None,
            "runtime_s": round(time.time() - T_START, 1)}


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
    """Write ``results/<name>.json`` with a provenance block (run id, commit, command, runtime).

    Values are stored at full precision; tables round them once when rendered
    (``scripts/render_results.py``)."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    payload = {"benchmark": name, "generated": time.strftime("%Y-%m-%d"), "python": platform.python_version(),
               "provenance": provenance(), **payload}
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
    return round(float(max(0.0, c - h)), 8), round(float(min(1.0, c + h)), 8)


def nb_interval(vals: list[float], n_train: int, n_test: int, lo: float = 0.0, hi: float = 1.0) -> dict[str, Any]:
    """Mean and Nadeau-Bengio corrected 95 % interval over repeated splits/folds, as numbers.

    Proportions near 0 or 1 get the interval on the logit scale (delta method),
    so bounds always stay inside ``[lo, hi]``."""
    from scipy import stats
    a = np.asarray(vals, dtype=float)
    m = float(a.mean())
    if len(a) < 2:
        return {"mean": m, "ci95": [m, m], "n_runs": int(len(a)), "method": "single run"}
    corr = 1 / len(a) + n_test / n_train
    t = float(stats.t.ppf(0.975, len(a) - 1))
    half = t * float(np.sqrt(a.var(ddof=1) * corr))
    lo_b, hi_b = m - half, m + half
    method = "Nadeau-Bengio corrected t"
    if lo_b < lo or hi_b > hi:
        eps = 0.5 / max(n_test, 1)
        p = np.clip(a, eps, 1 - eps)
        lg = np.log(p / (1 - p))
        lm = float(lg.mean())
        lh = t * float(np.sqrt(lg.var(ddof=1) * corr))
        lo_b, hi_b = 1 / (1 + np.exp(-(lm - lh))), 1 / (1 + np.exp(-(lm + lh)))
        method = "Nadeau-Bengio corrected t on the logit scale"
    return {"mean": m, "ci95": [float(max(lo, lo_b)), float(min(hi, hi_b))], "n_runs": int(len(a)),
            "method": method}


def t_interval(vals: list[float]) -> dict[str, Any]:
    """Mean and 95 % t-interval over independent seeds (seed variance only), as numbers."""
    from scipy import stats
    a = np.asarray(vals, dtype=float)
    m = float(a.mean())
    if len(a) < 2:
        return {"mean": m, "ci95": [m, m], "n_runs": int(len(a))}
    h = float(stats.t.ppf(0.975, len(a) - 1) * a.std(ddof=1) / np.sqrt(len(a)))
    return {"mean": m, "ci95": [m - h, m + h], "n_runs": int(len(a)), "min": float(a.min()), "max": float(a.max())}


def corrected_paired_t(a: list[float], b: list[float], n_train: int, n_test: int) -> dict[str, Any]:
    """Nadeau-Bengio corrected resampled paired t-test of ``b - a`` over the same splits."""
    from scipy import stats
    d = np.asarray(b, dtype=float) - np.asarray(a, dtype=float)
    k = len(d)
    m = float(d.mean())
    var = float(d.var(ddof=1)) * (1 / k + n_test / n_train) if k > 1 else 0.0
    if var == 0:
        return {"mean_diff": m, "ci95": [m, m], "t": None, "p": 1.0 if m == 0 else 0.0, "n_runs": k}
    tstat = m / np.sqrt(var)
    tc = float(stats.t.ppf(0.975, k - 1))
    return {"mean_diff": m, "ci95": [m - tc * np.sqrt(var), m + tc * np.sqrt(var)], "t": float(tstat),
            "p": float(2 * stats.t.sf(abs(tstat), k - 1)), "n_runs": k,
            "method": "Nadeau-Bengio corrected resampled paired t"}
