"""Static gate benchmark on EMBER 2018 raw features.

    SPECIMEN_DATA=... python benchmarks/bench_static.py [--limit N]

Compares three detonation gates on the same held-out split:

* ``mvp-heuristic``  - the original hand-weighted additive gate (ported);
* ``logreg``         - logistic regression on the full EMBER-style vector;
* ``lightgbm``       - LightGBM + TreeSHAP (the SPECIMEN static model).

It also answers the spec's research question for the gate: at a threshold
tuned on validation data for >= 99% malware recall, how many detonations
does the gate save, and how much malware does it wrongly skip?
"""
from __future__ import annotations

import argparse
import time

import numpy as np
from common import FIGURES, ROOT, binary_metrics, md_table, write_result
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from specimen.datasets import data_root, iter_ember
from specimen.ml.ember import StaticModel, heuristic_score, train, vectorize

TARGET_RECALL = 0.99


def load(limit: int | None) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[str]]:
    cache = data_root() / "cache" / f"ember_vec_{limit or 'all'}.npz"
    if cache.exists():
        d = np.load(cache)  # plain numeric / unicode arrays, no pickle
        return d["X"], d["y"], d["h"], list(d["fam"])
    X, y, h, fam = [], [], [], []
    t0 = time.time()
    for i, row in enumerate(iter_ember(limit=limit)):
        X.append(vectorize(row))
        y.append(row["label"])
        h.append(heuristic_score(row))
        fam.append(row.get("avclass") or "")
        if i % 10000 == 0:
            print(f"  vectorised {i} ({time.time() - t0:.0f}s)", flush=True)
    Xa, ya, ha = np.vstack(X), np.asarray(y), np.asarray(h)
    cache.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(cache, X=Xa, y=ya, h=ha, fam=np.asarray(fam, dtype=str))
    return Xa, ya, ha, fam


def gate_threshold(y: np.ndarray, s: np.ndarray, recall: float) -> float:
    mal = np.sort(s[y == 1])
    return float(mal[int(np.floor((1 - recall) * len(mal)))]) if len(mal) else 0.5


def gate_stats(y: np.ndarray, s: np.ndarray, thr: float) -> dict[str, float]:
    det = s >= thr
    return {
        "threshold": round(thr, 5),
        "detonations_saved_pct": round(100 * float((~det).mean()), 2),
        "benign_skipped_pct": round(100 * float((~det[y == 0]).mean()), 2),
        "malware_missed_pct": round(100 * float((~det[y == 1]).mean()), 2),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    X, y, h, _ = load(a.limit)
    print(f"EMBER rows: {len(y)} (malicious {int(y.sum())}, benign {int((y == 0).sum())})")
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.25, stratify=y, random_state=0)
    trf, va = train_test_split(tr, test_size=0.1, stratify=y[tr], random_state=1)

    t0 = time.time()
    booster = train(X[trf], y[trf])
    t_train = time.time() - t0
    s_va = booster.predict(X[va])
    t0 = time.time()
    s_lgb = booster.predict(X[te])
    t_pred = (time.time() - t0) / len(te) * 1e3

    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=300, C=0.1))
    Xl = np.log1p(np.abs(X)) * np.sign(X)
    lr.fit(Xl[trf], y[trf])
    s_lr, s_lr_va = lr.predict_proba(Xl[te])[:, 1], lr.predict_proba(Xl[va])[:, 1]

    rows, gates = [], []
    for name, s, sv in (("mvp-heuristic", h[te], h[va]), ("logreg", s_lr, s_lr_va), ("lightgbm", s_lgb, s_va)):
        m = binary_metrics(y[te], s)
        rows.append({"model": name, **m})
        g = gate_stats(y[te], s, gate_threshold(y[va], sv, TARGET_RECALL))
        gates.append({"gate": name, **g})
    gates.insert(0, {"gate": "mvp-policy (detonate every PE)", "threshold": "-", "detonations_saved_pct": 0.0,
                     "benign_skipped_pct": 0.0, "malware_missed_pct": 0.0})
    for r in rows:
        print(r)
    for g in gates:
        print(g)

    thr = gate_threshold(y[va], s_va, TARGET_RECALL)
    model = StaticModel(booster, thr, {"trained_on": "EMBER 2018 v2 (train_features_1 prefix)", "n_train": len(trf),
                                       "target_recall": TARGET_RECALL})
    model.save(ROOT / "models")
    # one explained example (highest-scoring malicious test sample)
    ex_i = te[int(np.argmax(s_lgb))]
    expl = model.explain(X[ex_i])

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import roc_curve
        FIGURES.mkdir(parents=True, exist_ok=True)
        fig, ax = plt.subplots(figsize=(5.2, 4))
        for name, s in (("MVP heuristic", h[te]), ("LogReg", s_lr), ("LightGBM", s_lgb)):
            fpr, tpr, _ = roc_curve(y[te], s)
            ax.plot(fpr, tpr, label=name)
        ax.set_xscale("log")
        ax.set_xlim(1e-4, 1)
        ax.set_xlabel("False positive rate (log)")
        ax.set_ylabel("True positive rate")
        ax.set_title("Static gate on EMBER 2018 (held-out 25%)")
        ax.legend(loc="lower right")
        ax.grid(alpha=0.3)
        fig.tight_layout()
        fig.savefig(FIGURES / "static_roc.png", dpi=110)
    except ImportError:
        pass

    write_result("static_ember", {
        "dataset": {"name": "EMBER 2018 v2 raw features (prefix)", "rows": int(len(y)),
                    "malicious": int(y.sum()), "benign": int((y == 0).sum()),
                    "split": "stratified random 75/25 (seed 0); single month 2018-01 in prefix"},
        "metrics": rows, "gate_at_99pct_recall": gates,
        "lightgbm_train_seconds": round(t_train, 1), "lightgbm_ms_per_sample": round(t_pred, 4),
        "example_explanation": expl,
        "published_reference": {"EMBER 2017 LightGBM (Anderson & Roth 2018)": {
            "roc_auc": 0.99911, "tpr@0.1%fpr": 0.9299, "tpr@1%fpr": 0.982}},
        "markdown": md_table(rows, ["model", "roc_auc", "tpr@0.1%fpr", "tpr@1%fpr", "accuracy", "f1"]) + "\n\n"
        + md_table(gates, ["gate", "threshold", "detonations_saved_pct", "benign_skipped_pct",
                           "malware_missed_pct"]),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
