"""Temporal EMBER-2018 evaluation of the static gate (train earlier, test later).

    SPECIMEN_DATA=... python benchmarks/bench_static_temporal.py [--train-per-month 15000] [--seeds 3]

Runs in the ``bench`` GitHub Actions workflow: it needs the full official
``ember_dataset_2018_2.tar.bz2`` (1.6 GB, pinned SHA-256) and ~8 GB RAM.

Protocol:

* stream every labelled row of the official archive and vectorise it with
  the *shipped* featuriser (``specimen.ml.ember.vectorize``, CRC32-hashed);
* deterministic hash subsample per month (``appeared``): train on Jan-Sep
  (at most ``--train-per-month`` rows per month), calibrate the 99 %-recall
  detonation threshold on October, test on November and December (at most
  ``--test-per-month`` rows per month);
* LightGBM (same settings as the shipped gate), one model per seed (the seed
  changes the training subsample and the booster seed);
* per test month: ROC AUC, TPR at 0.1 % / 1 % FPR, detonations saved and
  malware missed at the October threshold; plus a random split over the
  same months and volume, to show what a random split hides;
* baselines on the same temporal test rows: the MVP heuristic gate (no
  training; ported to EMBER raw features) and the "detonate every PE" policy;
* intervals: 95 % t-intervals over the seeds (seed variance only: the test
  rows are fixed) and, for seed 0, a percentile bootstrap over test rows;
* the seed-0 model with its October threshold is saved to ``models/`` (the
  ``static_*`` release asset used by ``specimen triage-ember``).

Published reference, same test months but not the same setup: the upstream
EMBER-2018 LightGBM benchmark (elastic/ember
``resources/ember2018-notebook.ipynb``) reaches ROC AUC 0.99643, 86.81 %
detection at 0.1 % FPR and 96.50 % at 1 % FPR, trained on all 600k labelled
Jan-Oct rows with EMBER's own 2,381-dimension features. SPECIMEN trains on a
132k-row Jan-Sep subsample with its own featuriser and holds October out for
calibration, so the gap mixes training volume and features with drift.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from collections import defaultdict

import numpy as np
from common import FIGURES, ROOT, binary_metrics, require_data, t_interval, tpr_at_fpr, write_result
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

from specimen.datasets import EMBER_TAR, data_root
from specimen.ml.ember import StaticModel, heuristic_score, train, vectorize

TRAIN_MONTHS = [f"2018-{m:02d}" for m in range(1, 10)]
CAL_MONTH = "2018-10"
TEST_MONTHS = ["2018-11", "2018-12"]
TARGET_RECALL = 0.99
UPSTREAM = {"roc_auc": 0.99643, "tpr@0.1%fpr": 0.8681, "tpr@1%fpr": 0.9650}


def lines():
    """Raw JSON lines of every .jsonl member (lbzip2 when available: much faster)."""
    path = data_root() / EMBER_TAR
    if shutil.which("lbzip2") and shutil.which("tar"):
        cmd = f"lbzip2 -dc '{path}' | tar -xO --wildcards '*features*.jsonl'"
        with subprocess.Popen(["bash", "-c", cmd], stdout=subprocess.PIPE, bufsize=1 << 20) as p:
            assert p.stdout is not None
            yield from p.stdout
        return
    import bz2
    import tarfile
    with bz2.open(path, "rb") as bz, tarfile.open(fileobj=bz, mode="r|") as tf:
        for m in tf:
            if m.isfile() and m.name.endswith(".jsonl"):
                f = tf.extractfile(m)
                if f is not None:
                    yield from f


def keep(sha: str, salt: str, rate: float) -> bool:
    return int(hashlib.sha256((salt + sha).encode()).hexdigest()[:8], 16) / 0xFFFFFFFF < rate


def collect(train_cap: int, test_cap: int) -> dict[str, dict[str, list]]:
    """Month -> {X, y}; rates sized from EMBER-2018's published month counts (~60k/100k)."""
    by: dict[str, dict[str, list]] = defaultdict(lambda: {"X": [], "y": [], "sha": [], "h": []})
    t0 = time.time()
    n = 0
    for raw in lines():
        n += 1
        try:
            row = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if row.get("label") not in (0, 1):
            continue
        month = str(row.get("appeared", ""))[:7]
        if month in TRAIN_MONTHS:
            rate = train_cap / 55_000
        elif month == CAL_MONTH:
            rate = test_cap / 55_000
        elif month in TEST_MONTHS:
            rate = test_cap / 100_000
        else:
            continue
        if not keep(row["sha256"], "specimen-temporal", min(1.0, rate * 1.15)):
            continue
        d = by[month]
        cap = train_cap if month in TRAIN_MONTHS else test_cap
        if len(d["y"]) >= cap:
            continue
        d["X"].append(vectorize(row).astype(np.float32))
        d["y"].append(int(row["label"]))
        d["sha"].append(row["sha256"])
        d["h"].append(heuristic_score(row))
        if n % 100_000 == 0:
            print(f"  {n} rows read, kept " + ", ".join(f"{m}:{len(v['y'])}" for m, v in sorted(by.items()))
                  + f" ({time.time() - t0:.0f}s)", flush=True)
    return by


def gate(y: np.ndarray, s: np.ndarray, thr: float) -> dict[str, float]:
    det = s >= thr
    return {"detonations_saved": float(1 - det.mean()),
            "malware_missed": float((~det[y == 1]).mean()),
            "benign_skipped": float((~det[y == 0]).mean()),
            "malware_share": float(y.mean())}


def boot_test_rows(y: np.ndarray, s: np.ndarray, n: int = 400, seed: int = 0) -> dict[str, list[float]]:
    """Percentile bootstrap over test rows of ROC AUC and TPR at 0.1 % / 1 % FPR."""
    rng = np.random.default_rng(seed)
    vals: dict[str, list[float]] = {"roc_auc": [], "tpr@0.1%fpr": [], "tpr@1%fpr": []}
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        vals["roc_auc"].append(roc_auc_score(y[i], s[i]))
        vals["tpr@0.1%fpr"].append(tpr_at_fpr(y[i], s[i], 1e-3))
        vals["tpr@1%fpr"].append(tpr_at_fpr(y[i], s[i], 1e-2))
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in vals.items()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-per-month", type=int, default=15_000)
    ap.add_argument("--test-per-month", type=int, default=50_000)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=600)
    a = ap.parse_args()
    require_data(EMBER_TAR)
    t0 = time.time()
    by = collect(a.train_per_month, a.test_per_month)
    counts = {m: {"rows": len(v["y"]), "malicious": int(sum(v["y"]))} for m, v in sorted(by.items())}
    print("collected", counts, f"{time.time() - t0:.0f}s", flush=True)
    stack = {m: (np.vstack(v["X"]), np.asarray(v["y"])) for m, v in by.items()}
    heur = {m: np.asarray(v["h"]) for m, v in by.items()}
    by.clear()
    Xc, yc = stack[CAL_MONTH]
    per_month, per_seed, random_rows = [], [], []
    for seed in range(a.seeds):
        rng = np.random.default_rng(seed)
        parts = []
        for m in TRAIN_MONTHS:
            X, y = stack[m]
            idx = rng.choice(len(y), size=int(0.9 * len(y)), replace=False)  # seed-dependent subsample
            parts.append((X[idx], y[idx]))
        Xtr = np.vstack([p[0] for p in parts])
        ytr = np.concatenate([p[1] for p in parts])
        booster = train(Xtr, ytr, seed=seed, rounds=a.rounds)
        sc = booster.predict(Xc)
        mal = np.sort(sc[yc == 1])
        thr = float(mal[int(np.floor((1 - TARGET_RECALL) * len(mal)))])
        pooled_y, pooled_s = [], []
        for m in TEST_MONTHS:
            X, y = stack[m]
            s = booster.predict(X)
            pooled_y.append(y)
            pooled_s.append(s)
            met = binary_metrics(y, s)
            per_month.append({"seed": seed, "month": m, "n": int(len(y)), "roc_auc": met["roc_auc"],
                              "tpr@0.1%fpr": met["tpr@0.1%fpr"], "tpr@1%fpr": met["tpr@1%fpr"], **gate(y, s, thr)})
            print(per_month[-1], flush=True)
        py, ps = np.concatenate(pooled_y), np.concatenate(pooled_s)
        per_seed.append({"seed": seed, "threshold": thr, "roc_auc": float(roc_auc_score(py, ps)),
                         "tpr@0.1%fpr": tpr_at_fpr(py, ps, 1e-3), "tpr@1%fpr": tpr_at_fpr(py, ps, 1e-2),
                         **gate(py, ps, thr)})
        if seed == 0:
            boot0 = boot_test_rows(py, ps)
            model = StaticModel(booster, thr, {
                "trained_on": "EMBER 2018 v2, labelled rows appeared 2018-01..2018-09 (month-stratified "
                              "subsample, seed 0)", "n_train": int(len(ytr)),
                "threshold_policy": f"{TARGET_RECALL:.0%} malware recall on {CAL_MONTH}",
                "evaluated_on": "2018-11..2018-12 (results/static_ember_temporal.json)", "rounds": a.rounds})
            model.save(ROOT / "models")
            # baselines on the same temporal test rows
            hy = np.concatenate([heur[m] for m in TEST_MONTHS])
            hcal = heur[CAL_MONTH]
            hmal = np.sort(hcal[yc == 1])
            hthr = float(hmal[int(np.floor((1 - TARGET_RECALL) * len(hmal)))])
            baselines = [
                {"protocol": "MVP heuristic gate (no training), same test rows",
                 "roc_auc": float(roc_auc_score(py, hy)), "tpr@0.1%fpr": tpr_at_fpr(py, hy, 1e-3),
                 "tpr@1%fpr": tpr_at_fpr(py, hy, 1e-2), "threshold": hthr, **gate(py, hy, hthr),
                 "roc_auc_95ci": boot_test_rows(py, hy, n=200)["roc_auc"]},
                {"protocol": "detonate every PE (what analyze does)", "roc_auc": None, "tpr@0.1%fpr": None,
                 "tpr@1%fpr": None, "detonations_saved": 0.0, "malware_missed": 0.0, "benign_skipped": 0.0},
            ]
        # random split over the same months and volume (what the v1.0 benchmark did)
        Xall = np.vstack([Xtr, Xc, *[stack[m][0] for m in TEST_MONTHS]])
        yall = np.concatenate([ytr, yc, *[stack[m][1] for m in TEST_MONTHS]])
        i_tr, i_te = train_test_split(np.arange(len(yall)), train_size=len(ytr), stratify=yall, random_state=seed)
        b2 = train(Xall[i_tr], yall[i_tr], seed=seed, rounds=a.rounds)
        yt, st = yall[i_te], b2.predict(Xall[i_te])
        random_rows.append({"seed": seed, "roc_auc": float(roc_auc_score(yt, st)), "tpr@0.1%fpr": tpr_at_fpr(yt, st, 1e-3),
                            "tpr@1%fpr": tpr_at_fpr(yt, st, 1e-2)})
        print("temporal", per_seed[-1], "random", random_rows[-1], f"{time.time() - t0:.0f}s", flush=True)
        del Xall, yall

    keys = ["roc_auc", "tpr@0.1%fpr", "tpr@1%fpr", "detonations_saved", "malware_missed", "benign_skipped"]
    summary = [{"protocol": "temporal (train Jan-Sep, calibrate Oct, test Nov-Dec)",
                **{k: t_interval([r[k] for r in per_seed]) for k in keys},
                "seed0_test_row_bootstrap_95ci": boot0},
               {"protocol": "random split, same months and volume",
                **{k: t_interval([r[k] for r in random_rows]) for k in keys[:3]}},
               {"protocol": "upstream EMBER-2018 LightGBM (all 600k Jan-Oct rows, EMBER features, Nov-Dec test)",
                **UPSTREAM}]
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6.4, 3.6))
        for k in ("tpr@1%fpr", "tpr@0.1%fpr", "detonations_saved"):
            ys = [np.mean([r[k] for r in per_month if r["month"] == m]) for m in TEST_MONTHS]
            ax.plot(TEST_MONTHS, ys, marker="o", label=k)
        ax.set_ylim(0, 1)
        ax.set_title("Static gate on later months (trained Jan-Sep 2018)")
        ax.legend()
        ax.grid(alpha=0.3)
        fig.tight_layout()
        FIGURES.mkdir(parents=True, exist_ok=True)
        fig.savefig(FIGURES / "static_temporal.png", dpi=110)
    except ImportError:
        pass
    write_result("static_ember_temporal", {
        "dataset": "EMBER 2018 v2 official archive (ember.elastic.co), labelled rows only",
        "featuriser": "specimen.ml.ember.vectorize (the shipped gate's 2,440-dim CRC32 feature space)",
        "months_collected": counts, "seeds": a.seeds, "rounds": a.rounds,
        "threshold_policy": f"{TARGET_RECALL:.0%} malware recall on {CAL_MONTH}",
        "summary": summary, "baselines_same_test_rows": baselines, "per_seed": per_seed, "per_month": per_month,
        "random_split": random_rows,
        "ci_method": "95 % t-interval over seeds (seed variance only; test rows fixed); seed-0 percentile "
                     "bootstrap over test rows",
        "released_model": "seed 0 -> models/static_lgbm.txt + static_meta.json (bench artefact, release asset)",
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
