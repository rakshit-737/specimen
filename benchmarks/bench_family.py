"""Family attribution on the Avast-CTU CAPEv2 dataset (reduced reports).

    SPECIMEN_DATA=... python benchmarks/bench_family.py

Temporal split of the dataset authors (train < 2019-08-01 <= test).
Compared:

* ``mvp-jaccard``      - the MVP family matcher: nearest ATT&CK-technique
                         set (Jaccard), majority family of the nearest set;
* ``static-only``      - hashed static.pe tokens + logistic regression;
* ``behaviour-only``   - hashed normalised behaviour tokens + LR;
* ``behaviour+static`` - both token sets (the SPECIMEN family model).

Published reference (Bosansky et al. 2022, HMIL on reduced reports):
94.5 % test accuracy with behaviour+static, ~63 % static-only.
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict

import numpy as np
from common import FIGURES, ROOT, md_table, write_result
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from specimen.ml.avast import load_cache
from specimen.ml.family import FamilyModel


def jaccard_baseline(train: list[dict], test: list[dict]) -> list[str]:
    by_set: dict[frozenset, Counter] = defaultdict(Counter)
    for r in train:
        by_set[frozenset(t for t in r["beh"] if t.startswith("tech:"))][r["family"]] += 1
    protos = list(by_set.items())
    cache: dict[frozenset, str] = {}
    out = []
    for r in test:
        s = frozenset(t for t in r["beh"] if t.startswith("tech:"))
        if s not in cache:
            best, bj, bn = None, -1.0, 0
            for p, cnt in protos:
                j = len(s & p) / len(s | p) if s | p else 1.0
                n = sum(cnt.values())
                if j > bj or (j == bj and n > bn):
                    best, bj, bn = cnt, j, n
            cache[s] = best.most_common(1)[0][0] if best else "?"
        out.append(cache[s])
    return out


def main() -> int:
    t0 = time.time()
    recs = list(load_cache())
    train = [r for r in recs if r["split"] == "train"]
    test = [r for r in recs if r["split"] == "test"]
    fams = sorted({r["family"] for r in recs})
    print(f"loaded {len(recs)} records ({len(train)} train / {len(test)} test) in {time.time() - t0:.0f}s")
    y_te = [r["family"] for r in test]

    variants = {
        "static-only": lambda r: r["static"],
        "behaviour-only": lambda r: r["beh"],
        "behaviour+static": lambda r: r["beh"] + r["static"],
    }
    rows, preds = [], {}
    t = time.time()
    preds["mvp-jaccard"] = jaccard_baseline(train, test)
    timing = {"mvp-jaccard": time.time() - t}
    models = {}
    for name, f in variants.items():
        t = time.time()
        m = FamilyModel.fit([f(r) for r in train], [r["family"] for r in train])
        preds[name] = m.predict([f(r) for r in test])
        timing[name] = time.time() - t
        models[name] = m
        print(f"  {name}: {timing[name]:.0f}s")
    for name, p in preds.items():
        per = {f: round(float(np.mean([a == b for a, b in zip(y_te, p) if a == f])), 4) for f in fams}
        rows.append({"model": name, "accuracy": round(accuracy_score(y_te, p), 4),
                     "macro_f1": round(f1_score(y_te, p, average="macro"), 4),
                     "fit+predict_s": round(timing[name], 1), "per_family_recall": per})
        print(name, rows[-1]["accuracy"], rows[-1]["macro_f1"])
    rows.append({"model": "published HMIL behaviour+static (Bosansky 2022)", "accuracy": 0.945, "macro_f1": "-"})
    rows.append({"model": "published HMIL static-only (Bosansky 2022)", "accuracy": "~0.63", "macro_f1": "-"})

    # ship the most accurate variant; the pipeline reads which token sets it needs
    best_name = max(variants, key=lambda n: accuracy_score(y_te, preds[n]))
    best = models[best_name]
    best.save(ROOT / "models", {"trained_on": "Avast-CTU CAPEv2 reduced reports, split=train",
                                "variant": best_name, "tokens": best_name.split("+") if "+" in best_name
                                else [best_name.replace("-only", "")], "n_train": len(train),
                                "classes": best.classes})
    # an explained test prediction
    ex = test[0]
    f = variants[best_name]
    fam_pred = best.predict([f(ex)])[0]
    expl = best.explain(f(ex), fam_pred)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        cm = confusion_matrix(y_te, preds[best_name], labels=fams, normalize="true")
        fig, ax = plt.subplots(figsize=(6.4, 5.4))
        im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=1)
        ax.set_xticks(range(len(fams)), fams, rotation=45, ha="right")
        ax.set_yticks(range(len(fams)), fams)
        for i in range(len(fams)):
            for j in range(len(fams)):
                if cm[i, j] >= 0.01:
                    ax.text(j, i, f"{cm[i, j]:.2f}", ha="center", va="center", fontsize=7,
                            color="white" if cm[i, j] > 0.6 else "black")
        ax.set_xlabel("predicted")
        ax.set_ylabel("true")
        ax.set_title("Family model, Avast-CTU temporal test split")
        fig.colorbar(im, fraction=0.046)
        fig.tight_layout()
        FIGURES.mkdir(parents=True, exist_ok=True)
        fig.savefig(FIGURES / "family_confusion.png", dpi=110)
    except ImportError:
        pass

    counts = Counter(r["family"] for r in recs)
    write_result("family_avast", {
        "dataset": {"name": "Avast-CTU Public CAPEv2 (reduced reports)", "reports": len(recs),
                    "train": len(train), "test": len(test), "split": "date < 2019-08-01 -> train",
                    "families": dict(sorted(counts.items()))},
        "metrics": rows, "example": {"sha256": ex["sha256"], "true": ex["family"], "pred": fam_pred,
                                     "top_tokens": expl},
        "markdown": md_table(rows, ["model", "accuracy", "macro_f1", "fit+predict_s"]),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
