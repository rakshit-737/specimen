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

Open-set threshold. The abstention threshold tau (below it the pipeline
reports "unknown (closest: X)") is chosen on the same temporal validation
slice, never on test: models fitted on train runs before 2019-06-01 score the
validation runs (known-family coverage) and, leaving one family out at a
time, the held-out family's validation runs (unseen-family acceptance); tau is
the largest grid value that keeps >= 95 % known-family coverage on
validation. It is then applied unchanged to the test split, where coverage,
covered accuracy and unseen-family acceptance (leave-one-family-out again,
models fitted on all train runs) get Wilson CIs.
"""
from __future__ import annotations

import argparse
import time
from collections import Counter, defaultdict

import numpy as np
from common import FIGURES, ROOT, md_table, require_data, wilson, write_result
from scipy import stats
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from specimen.ml.avast import load_cache
from specimen.ml.family import FamilyModel

VAL_START = "2019-06-01"
TAUS = [round(0.30 + 0.05 * i, 2) for i in range(14)]  # 0.30 .. 0.95
TARGET_COVERAGE = 0.95


def lofo_max_p(f, fit_on: list[dict], score_on: list[dict], fams: list[str]) -> tuple[np.ndarray, dict]:
    """Leave-one-family-out: fit on ``fit_on`` minus a family, top probability of that family's ``score_on`` runs."""
    held: list[float] = []
    per: dict[str, dict] = {}
    for fam in fams:
        ho = [r for r in score_on if r["family"] == fam]
        tr = [r for r in fit_on if r["family"] != fam]
        if not ho or len({r["family"] for r in tr}) < 2:
            continue
        m = FamilyModel.fit([f(r) for r in tr], [r["family"] for r in tr], max_iter=150)
        pm = m.proba([f(r) for r in ho]).max(axis=1)
        held += pm.tolist()
        per[fam] = {"n": len(ho), "median_max_p": float(np.median(pm))}
        print(f"  LOFO {fam}: n {len(ho)}, median max p {per[fam]['median_max_p']:.3f}", flush=True)
    return np.asarray(held), per


def coverage_curve(known_p: np.ndarray, known_ok: np.ndarray, held: np.ndarray) -> list[dict]:
    rows = []
    for tau in TAUS:
        cov = known_p >= tau
        rows.append({"tau": tau, "known_coverage": float(cov.mean()),
                     "known_accuracy_covered": float(known_ok[cov].mean()) if cov.any() else float("nan"),
                     "unseen_family_accepted": float((held >= tau).mean()) if len(held) else float("nan")})
    return rows


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
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    require_data("cache/avast_tokens.jsonl.gz")
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
        per = {f: float(np.mean([a == b for a, b in zip(y_te, p) if a == f])) for f in fams}
        rows.append({"model": name, "accuracy": float(accuracy_score(y_te, p)),
                     "macro_f1": float(f1_score(y_te, p, average="macro")),
                     "fit+predict_s": round(timing[name], 1), "per_family_recall": per})
        print(name, rows[-1]["accuracy"], rows[-1]["macro_f1"])
    novel_mask = np.asarray([frozenset(r["beh"]) not in train_sets for r in test])
    for row in rows:
        p = np.asarray(preds[row["model"]])
        ok = p == np.asarray(y_te)
        row["accuracy_95ci"] = list(wilson(int(ok.sum()), len(ok)))
        row["novel_behaviour_accuracy"] = float(ok[novel_mask].mean())
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
    val_acc, sub_models = {}, {}
    y_val = np.asarray([r["family"] for r in val])
    for name, f in variants.items():
        m = FamilyModel.fit([f(r) for r in sub], [r["family"] for r in sub])
        sub_models[name] = m
        val_acc[name] = float(accuracy_score(y_val, m.predict([f(r) for r in val])))
    best_name = max(variants, key=lambda n: val_acc[n])
    print("validation accuracy", val_acc, "->", best_name, flush=True)
    best = models[best_name]
    f = variants[best_name]

    # open set: tau chosen on the validation slice only
    pv = sub_models[best_name].proba([f(r) for r in val])
    val_known_p = pv.max(axis=1)
    val_ok = np.asarray(sub_models[best_name].classes)[pv.argmax(axis=1)] == y_val
    print("open set, validation (fit < 2019-06-01, score 2019-06/07):", flush=True)
    val_held, val_lofo = lofo_max_p(f, sub, val, fams)
    val_curve = coverage_curve(val_known_p, val_ok, val_held)
    ok_taus = [c["tau"] for c in val_curve if c["known_coverage"] >= TARGET_COVERAGE]
    tau = max(ok_taus) if ok_taus else min(TAUS)
    # ... applied unchanged to test
    pt = best.proba([f(r) for r in test])
    known_p = pt.max(axis=1)
    test_ok = np.asarray(preds[best_name]) == np.asarray(y_te)
    print("open set, test (fit on all train, score test):", flush=True)
    held, lofo = lofo_max_p(f, train, test, fams)
    cov = known_p >= tau
    acc_k, acc_n = int(test_ok[cov].sum()), int(cov.sum())
    acc_unseen = int((held >= tau).sum())
    test_at_tau = {
        "tau": tau,
        "known_coverage": float(cov.mean()), "known_coverage_95ci": list(wilson(int(cov.sum()), len(cov))),
        "known_accuracy_covered": acc_k / acc_n if acc_n else float("nan"),
        "known_accuracy_covered_95ci": list(wilson(acc_k, acc_n)),
        "unseen_family_accepted": acc_unseen / len(held) if len(held) else float("nan"),
        "unseen_family_accepted_95ci": list(wilson(acc_unseen, len(held))),
        "n_known_test": int(len(cov)), "n_unseen_test": int(len(held)),
    }
    open_set = {"protocol": "tau = largest grid value with >= 95 % known-family coverage on the temporal "
                            "validation slice (models fitted on train runs before 2019-06-01; leave-one-family-out "
                            "for unseen families); applied unchanged to test",
                "abstain_below": tau, "selected_on": f"validation {VAL_START}..2019-07-31",
                "validation_curve": val_curve, "validation_lofo": val_lofo,
                "n_validation": len(val), "n_validation_unseen": int(len(val_held)),
                "test_at_tau": test_at_tau,
                "test_curve_for_reference": coverage_curve(known_p, test_ok, held),
                "test_lofo": lofo}
    print("open set", {k: v for k, v in open_set.items() if "curve" not in k and "lofo" not in k}, flush=True)
    best.save(ROOT / "models", {"trained_on": "Avast-CTU CAPEv2 reduced reports, split=train",
                                "variant": best_name, "tokens": best_name.split("+") if "+" in best_name
                                else [best_name.replace("-only", "")], "n_train": len(train),
                                "classes": best.classes, "abstain_below": tau,
                                "variant_selected_on": f"temporal validation {VAL_START}..2019-07-31 (accuracy)",
                                "abstain_selected_on": f"temporal validation {VAL_START}..2019-07-31 "
                                                       f"(largest tau with >= 95 % known-family coverage)",
                                "val_accuracy": val_acc})
    # an explained test prediction
    ex = test[0]
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
        "mcnemar": mcnemar, "novel_test_share": float(novel_mask.mean()), "open_set": open_set,
        "ci_method": "Wilson 95 % on test accuracy; exact McNemar (binomial)",
        "example": {"sha256": ex["sha256"], "true": ex["family"], "pred": fam_pred,
                                     "top_tokens": expl},
        "markdown": md_table(rows, ["model", "accuracy", "accuracy_95ci", "novel_behaviour_accuracy", "macro_f1",
                                    "fit+predict_s"]),
    })
    print(f"done in {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
