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
  same months and volume, to show what a random split hides.

Published like-for-like reference: upstream EMBER-2018 LightGBM benchmark
(elastic/ember ``resources/ember2018-notebook.ipynb``): ROC AUC 0.99643,
86.81 % detection at 0.1 % FPR, 96.50 % at 1 % FPR, trained on all 600k
labelled train rows (Jan-Oct) and tested on the 200k test rows (Nov-Dec).
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
from common import FIGURES, binary_metrics, md_table, write_result
from sklearn.model_selection import train_test_split

from specimen.datasets import EMBER_TAR, data_root
from specimen.ml.ember import train, vectorize

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
    by: dict[str, dict[str, list]] = defaultdict(lambda: {"X": [], "y": [], "sha": []})
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
        if n % 100_000 == 0:
            print(f"  {n} rows read, kept " + ", ".join(f"{m}:{len(v['y'])}" for m, v in sorted(by.items()))
                  + f" ({time.time() - t0:.0f}s)", flush=True)
    return by


def gate(y: np.ndarray, s: np.ndarray, thr: float) -> dict[str, float]:
    det = s >= thr
    return {"detonations_saved": round(float(1 - det.mean()), 4),
            "malware_missed": round(float((~det[y == 1]).mean()), 4),
            "benign_skipped": round(float((~det[y == 0]).mean()), 4),
            "malware_share": round(float(y.mean()), 4)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-per-month", type=int, default=15_000)
    ap.add_argument("--test-per-month", type=int, default=50_000)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=600)
    a = ap.parse_args()
    t0 = time.time()
    by = collect(a.train_per_month, a.test_per_month)
    counts = {m: {"rows": len(v["y"]), "malicious": int(sum(v["y"]))} for m, v in sorted(by.items())}
    print("collected", counts, f"{time.time() - t0:.0f}s", flush=True)
    stack = {m: (np.vstack(v["X"]), np.asarray(v["y"])) for m, v in by.items()}
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
        met = binary_metrics(py, ps)
        per_seed.append({"seed": seed, "threshold": round(thr, 5), "roc_auc": met["roc_auc"],
                         "tpr@0.1%fpr": met["tpr@0.1%fpr"], "tpr@1%fpr": met["tpr@1%fpr"], **gate(py, ps, thr)})
        # random split over the same months and volume (what the v1.0 benchmark did)
        Xall = np.vstack([Xtr, Xc, *[stack[m][0] for m in TEST_MONTHS]])
        yall = np.concatenate([ytr, yc, *[stack[m][1] for m in TEST_MONTHS]])
        i_tr, i_te = train_test_split(np.arange(len(yall)), train_size=len(ytr), stratify=yall, random_state=seed)
        b2 = train(Xall[i_tr], yall[i_tr], seed=seed, rounds=a.rounds)
        m2 = binary_metrics(yall[i_te], b2.predict(Xall[i_te]))
        random_rows.append({"seed": seed, "roc_auc": m2["roc_auc"], "tpr@0.1%fpr": m2["tpr@0.1%fpr"],
                            "tpr@1%fpr": m2["tpr@1%fpr"]})
        print("temporal", per_seed[-1], "random", random_rows[-1], f"{time.time() - t0:.0f}s", flush=True)
        del Xall, yall

    def agg(rows: list[dict], k: str) -> str:
        v = np.asarray([r[k] for r in rows], dtype=float)
        return f"{v.mean():.4f} (min {v.min():.4f}, max {v.max():.4f})"

    keys = ["roc_auc", "tpr@0.1%fpr", "tpr@1%fpr", "detonations_saved", "malware_missed", "benign_skipped"]
    summary = [{"protocol": "temporal (train Jan-Sep, calibrate Oct, test Nov-Dec)",
                **{k: agg(per_seed, k) for k in keys}},
               {"protocol": "random split, same months and volume",
                **{k: agg(random_rows, k) for k in keys[:3]}},
               {"protocol": "upstream EMBER-2018 LightGBM (all 600k train rows, Nov-Dec test)", **UPSTREAM}]
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
        "summary": summary, "per_seed": per_seed, "per_month": per_month, "random_split": random_rows,
        "markdown": md_table(summary, ["protocol", *keys]),
        "runtime_s": round(time.time() - t0, 1),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
