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

The shipped variant is chosen on a *temporal validation slice* (train runs
dated 2019-06-01 .. 2019-07-31, models fitted on earlier runs), never on the
test split. Accuracies get Wilson 95 % CIs, behaviour-only vs
behaviour+static a McNemar test, and a "novel behaviour" subset (test
reports whose behaviour-token set never occurs in train) is reported.
The logistic regression is deterministic (lbfgs), so seeds add no variance.

Open-set check: leave-one-family-out for the shipped variant (train on 9
families, score the held-out family's test reports) gives the abstention
threshold below which the pipeline reports "unknown family".
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict

import numpy as np
from common import FIGURES, ROOT, md_table, wilson, write_result
from scipy import stats
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from specimen.ml.avast import load_cache
from specimen.ml.family import FamilyModel

VAL_START = "2019-06-01"


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
    train_sets = {frozenset(r["beh"]) for r in train}

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
    novel_mask = np.asarray([frozenset(r["beh"]) not in train_sets for r in test])
    for row in rows:
        p = np.asarray(preds[row["model"]])
        ok = p == np.asarray(y_te)
        row["accuracy_95ci"] = list(wilson(int(ok.sum()), len(ok)))
        row["novel_behaviour_accuracy"] = round(float(ok[novel_mask].mean()), 4)
        row["novel_95ci"] = list(wilson(int(ok[novel_mask].sum()), int(novel_mask.sum())))
    a_ok = np.asarray(preds["behaviour-only"]) == np.asarray(y_te)
    b_ok = np.asarray(preds["behaviour+static"]) == np.asarray(y_te)
    n01, n10 = int((a_ok & ~b_ok).sum()), int((~a_ok & b_ok).sum())
    mcnemar = {"a": "behaviour-only", "b": "behaviour+static", "a_right_b_wrong": n01, "a_wrong_b_right": n10,
               "p_value": float(stats.binomtest(min(n01, n10), n01 + n10, 0.5).pvalue) if n01 + n10 else 1.0}
    print("mcnemar", mcnemar, "novel share", novel_mask.mean())
    rows.append({"model": "published HMIL behaviour+static (Bosansky 2022)", "accuracy": 0.945, "macro_f1": "-"})
    rows.append({"model": "published HMIL static-only (Bosansky 2022)", "accuracy": "~0.63", "macro_f1": "-"})

    # choose the shipped variant on the temporal validation slice (never on test)
    sub = [r for r in train if r["date"] < VAL_START]
    val = [r for r in train if r["date"] >= VAL_START]
    val_acc = {}
    for name, f in variants.items():
        m = FamilyModel.fit([f(r) for r in sub], [r["family"] for r in sub])
        val_acc[name] = round(float(accuracy_score([r["family"] for r in val], m.predict([f(r) for r in val]))), 4)
    best_name = max(variants, key=lambda n: val_acc[n])
    print("validation accuracy", val_acc, "->", best_name)
    best = models[best_name]
    # open-set: leave one family out, max-probability of its test reports
    f = variants[best_name]
    known_p = best.proba([f(r) for r in test]).max(axis=1)
    lofo = {}
    held_max: list[float] = []
    for fam in fams:
        tr = [r for r in train if r["family"] != fam]
        ho = [r for r in test if r["family"] == fam]
        if not ho:
            continue
        m = FamilyModel.fit([f(r) for r in tr], [r["family"] for r in tr], max_iter=150)
        pm = m.proba([f(r) for r in ho]).max(axis=1)
        held_max += pm.tolist()
        lofo[fam] = {"n": len(ho), "median_max_p": round(float(np.median(pm)), 4)}
        print(f"  LOFO {fam}: median max p {lofo[fam]['median_max_p']}", flush=True)
    held = np.asarray(held_max)
    curve = []
    for tau in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
        cov = known_p >= tau
        acc_cov = float((np.asarray(preds[best_name]) == np.asarray(y_te))[cov].mean()) if cov.any() else float("nan")
        curve.append({"tau": tau, "known_coverage": round(float(cov.mean()), 4), "known_accuracy_covered": round(acc_cov, 4),
                      "unseen_family_accepted": round(float((held >= tau).mean()), 4)})
    tau = next((c["tau"] for c in reversed(curve) if c["known_coverage"] >= 0.95), 0.5)
    open_set = {"protocol": "leave-one-family-out (train 9 families, score held-out family test reports)",
                "per_family": lofo, "risk_coverage": curve, "abstain_below": tau}
    print("open set", open_set)
    best.save(ROOT / "models", {"trained_on": "Avast-CTU CAPEv2 reduced reports, split=train",
                                "variant": best_name, "tokens": best_name.split("+") if "+" in best_name
                                else [best_name.replace("-only", "")], "n_train": len(train),
                                "classes": best.classes, "abstain_below": tau,
                                "selected_on": f"temporal validation {VAL_START}..2019-07-31", "val_accuracy": val_acc})
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
        "metrics": rows, "selection": {"validation_accuracy": val_acc, "shipped": best_name,
                                       "validation_slice": f"train runs dated >= {VAL_START}"},
        "mcnemar": mcnemar, "novel_test_share": round(float(novel_mask.mean()), 4), "open_set": open_set,
        "ci_method": "Wilson 95 % on test accuracy; exact McNemar (binomial)",
        "example": {"sha256": ex["sha256"], "true": ex["family"], "pred": fam_pred,
                                     "top_tokens": expl},
        "markdown": md_table(rows, ["model", "accuracy", "accuracy_95ci", "novel_behaviour_accuracy", "macro_f1",
                                    "fit+predict_s"]),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
