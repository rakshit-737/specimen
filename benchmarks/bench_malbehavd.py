"""Behavioural malicious-vs-benign on MalbehavD-V1 (Cuckoo API sequences).

    SPECIMEN_DATA=... python benchmarks/bench_malbehavd.py

Every sample goes through the same path as a live run: API sequence ->
``api_sequence_to_trace`` -> trace features. Compared (70/30 stratified
split as in the dataset paper, plus 5-fold CV):

* ``mvp-synthetic``   - the MVP behaviour scorer (logistic regression trained
                        on the synthetic corpus, ATT&CK-mapped features);
* ``attack-features`` - the same 9 explainable features, retrained on real data;
* ``api-ngram-lr``    - SPECIMEN tokens (API unigrams+bigrams, TF-IDF) + LR;
* ``api-ngram-lgbm``  - same tokens, LightGBM.

Published: MalDetConv (CNN-BiGRU) 96.10 % accuracy, MalDy (TF-IDF+XGBoost)
95.59 % on the same dataset with a 70/30 split (Maniriho et al. 2022).

Protocols reported side by side:

* ``paper``     - random stratified 70/30 on all 2,570 rows (the paper's
                  protocol; 42-45 % of test rows have an exact duplicate
                  sequence in train);
* ``dedup``     - one row per distinct API sequence (1,601 rows) before a
                  stratified 70/30 split, so no test sequence is seen in train;
* ``pipeline``  - a *simulation* of the shipped routing (the shipped JSON
                  model is fitted on all rows, so it cannot be scored on
                  them): per split, an LR fitted on the training rows scores
                  traces with >= ``api_behaviour.MIN_CALLS`` calls and the MVP
                  scorer the shorter ones; p >= 0.5 counts as "not benign"
                  (the report labels p >= 0.8 "malicious", also reported).

Intervals over repeated splits/folds use the Nadeau-Bengio correction, on the
logit scale when a proportion is close to 0 or 1 (bounds stay in [0, 1]).
"""
from __future__ import annotations

import argparse
import hashlib

import numpy as np
from common import ROOT, binary_metrics, bootstrap_ci, md_table, nb_interval, require_data, write_result
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split

from specimen.adapters.api_seq import api_sequence_to_trace
from specimen.api_behaviour import MIN_CALLS, ApiBehaviourModel, ngrams
from specimen.datasets import iter_malbehavd
from specimen.scoring import featurize, score

SEEDS = [0, 1, 2, 3, 4]


def fit_predict(name: str, tr: np.ndarray, te: np.ndarray, docs: list[list[str]], F: np.ndarray,
                y: np.ndarray, mvp: np.ndarray) -> np.ndarray:
    if name == "mvp-synthetic":
        return mvp[te]
    if name == "attack-features":
        m = LogisticRegression(max_iter=2000).fit(F[tr], y[tr])
        return m.predict_proba(F[te])[:, 1]
    vec = TfidfVectorizer(analyzer=lambda d: d, min_df=2, sublinear_tf=True)
    Xtr = vec.fit_transform([docs[i] for i in tr])
    Xte = vec.transform([docs[i] for i in te])
    if name == "api-ngram-lr":
        return LogisticRegression(C=10, max_iter=3000).fit(Xtr, y[tr]).predict_proba(Xte)[:, 1]
    import lightgbm as lgb
    m = lgb.LGBMClassifier(n_estimators=400, learning_rate=0.05, num_leaves=31, verbose=-1, random_state=0)
    return m.fit(Xtr.astype(np.float32), y[tr]).predict_proba(Xte.astype(np.float32))[:, 1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", action="store_true",
                    help="overwrite the shipped specimen/data/api_behaviour.json with the refit (default: only compare)")
    a = ap.parse_args()
    require_data("malbehavd/MalBehavD-V1-dataset.csv")
    rows = list(iter_malbehavd())
    y = np.asarray([lab for _, lab, _ in rows])
    traces = [api_sequence_to_trace(apis, sha) for sha, _, apis in rows]
    docs = [ngrams(apis) for _, _, apis in rows]
    F = np.asarray([featurize(t) for t in traces])
    mvp = np.asarray([score(t).probability for t in traces])
    print(f"MalbehavD-V1: {len(y)} samples ({int(y.sum())} malicious)")
    names = ["mvp-synthetic", "attack-features", "api-ngram-lr", "api-ngram-lgbm"]
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.3, stratify=y, random_state=0)
    holdout = []
    for n in names:
        s = fit_predict(n, tr, te, docs, F, y, mvp)
        m = binary_metrics(y[te], s)
        lo, hi = bootstrap_ci(y[te], s, "accuracy")
        alo, ahi = bootstrap_ci(y[te], s, "roc_auc")
        holdout.append({"model": n, **m, "accuracy_95ci": [lo, hi], "roc_auc_95ci": [alo, ahi]})
        print(holdout[-1])
    # repeated 70/30 splits over 5 seeds, and 5-fold CV repeated over 5 seeds
    seeds, cv = [], []
    for n in names:
        accs, aucs, f1s = [], [], []
        for sd in SEEDS:
            str_, ste = train_test_split(idx, test_size=0.3, stratify=y, random_state=sd)
            m = binary_metrics(y[ste], fit_predict(n, str_, ste, docs, F, y, mvp))
            accs.append(m["accuracy"])
            aucs.append(m["roc_auc"])
            f1s.append(m["f1"])
        nt = int(round(0.3 * len(y)))
        seeds.append({"model": n, "accuracy": nb_interval(accs, len(y) - nt, nt),
                      "roc_auc": nb_interval(aucs, len(y) - nt, nt),
                      "f1": nb_interval(f1s, len(y) - nt, nt), "accuracy_sd": float(np.std(accs, ddof=1)),
                      "runs": accs})
        print(seeds[-1])
        accs, aucs = [], []
        for sd in SEEDS:
            for ftr, fte in StratifiedKFold(5, shuffle=True, random_state=sd).split(idx, y):
                m = binary_metrics(y[fte], fit_predict(n, ftr, fte, docs, F, y, mvp))
                accs.append(m["accuracy"])
                aucs.append(m["roc_auc"])
        cv.append({"model": n, "cv_accuracy": nb_interval(accs, len(y) * 4 // 5, len(y) // 5),
                   "cv_roc_auc": nb_interval(aucs, len(y) * 4 // 5, len(y) // 5)})
        print(cv[-1])
    # duplicate-aware protocols
    key = [hashlib.sha256("".join(a).encode()).hexdigest() for _, _, a in rows]
    first: dict[str, int] = {}
    for i, k in enumerate(key):
        first.setdefault(k, i)
    uniq = np.asarray(sorted(first.values()))
    dup_stats = {"rows": int(len(y)), "distinct_sequences": int(len(uniq)),
                 "rows_in_duplicate_groups": int(sum(key.count(k) > 1 for k in key)),
                 "distinct_malicious": int(y[uniq].sum())}
    seen_in_train, seen_acc, unseen_acc = [], [], []
    dedup, pipe, short_lr, short_mvp, mal_at_08 = [], [], [], [], []
    for sd in SEEDS:
        str_, ste = train_test_split(idx, test_size=0.3, stratify=y, random_state=sd)
        trk = {key[i] for i in str_}
        seen = np.asarray([key[i] in trk for i in ste])
        s_lr = fit_predict("api-ngram-lr", str_, ste, docs, F, y, mvp)
        pred = (s_lr >= 0.5) == (y[ste] == 1)
        seen_in_train.append(float(seen.mean()))
        seen_acc.append(float(pred[seen].mean()))
        unseen_acc.append(float(pred[~seen].mean()))
        # shipped routing: short traces -> MVP scorer
        short = np.asarray([len(rows[i][2]) < MIN_CALLS for i in ste])
        routed = np.where(short, mvp[ste], s_lr)
        pipe.append(binary_metrics(y[ste], routed))
        mal_at_08.append(float((routed[y[ste] == 1] >= 0.8).mean()))
        s20 = np.asarray([len(rows[i][2]) < 20 for i in ste])
        short_lr.append(float(((s_lr[s20] >= 0.5) == (y[ste][s20] == 1)).mean()))
        short_mvp.append(float(((mvp[ste][s20] >= 0.5) == (y[ste][s20] == 1)).mean()))
    for n in ("api-ngram-lr", "api-ngram-lgbm", "attack-features"):
        accs, aucs = [], []
        for sd in SEEDS:
            dtr, dte = train_test_split(uniq, test_size=0.3, stratify=y[uniq], random_state=sd)
            m = binary_metrics(y[dte], fit_predict(n, dtr, dte, docs, F, y, mvp))
            accs.append(m["accuracy"])
            aucs.append(m["roc_auc"])
        nt = int(round(0.3 * len(uniq)))
        dedup.append({"model": n, "accuracy": nb_interval(accs, len(uniq) - nt, nt),
                      "roc_auc": nb_interval(aucs, len(uniq) - nt, nt), "runs": accs})
        print("dedup", dedup[-1])
    nt = int(round(0.3 * len(y)))
    leakage = {**dup_stats,
               "test_rows_with_exact_duplicate_in_train": nb_interval(seen_in_train, len(y) - nt, nt),
               "lr_accuracy_on_seen_rows": nb_interval(seen_acc, len(y) - nt, nt),
               "lr_accuracy_on_unseen_rows": nb_interval(unseen_acc, len(y) - nt, nt)}
    pipeline_path = {"what": "simulated shipped routing: per-split LR for traces with >= MIN_CALLS calls, MVP "
                             "scorer otherwise; p >= 0.5 counts as not benign",
                     "min_calls": MIN_CALLS,
                     "short_trace_share": float(np.mean([len(a) < MIN_CALLS for _, _, a in rows])),
                     "share_under_20_calls": float(np.mean([len(a) < 20 for _, _, a in rows])),
                     "accuracy": nb_interval([p["accuracy"] for p in pipe], len(y) - nt, nt),
                     "recall_at_0.5": nb_interval([p["recall"] for p in pipe], len(y) - nt, nt),
                     "malicious_recall_at_0.8": nb_interval(mal_at_08, len(y) - nt, nt),
                     "roc_auc": nb_interval([p["roc_auc"] for p in pipe], len(y) - nt, nt),
                     "traces_under_20_calls_lr_accuracy": nb_interval(short_lr, len(y) - nt, nt),
                     "traces_under_20_calls_mvp_accuracy": nb_interval(short_mvp, len(y) - nt, nt)}
    print("leakage", leakage)
    print("pipeline", pipeline_path)
    # the pipeline scorer: TF-IDF + LR on all rows, exported as pure-Python JSON (with --export)
    vec = TfidfVectorizer(analyzer=lambda d: d, min_df=2, sublinear_tf=True)
    X = vec.fit_transform(docs)
    lr = LogisticRegression(C=10, max_iter=3000).fit(X, y)
    if a.export:
        vocab = vec.get_feature_names_out()
        model = ApiBehaviourModel(dict(zip(vocab, vec.idf_.astype(float))),
                                  dict(zip(vocab, lr.coef_[0].astype(float))), float(lr.intercept_[0]),
                                  {"trained_on": "MalbehavD-V1", "n_train": int(len(y)),
                                   "features": "API uni+bigram sublinear TF-IDF", "C": 10})
        model.save(ROOT / "specimen" / "data")
    shipped = ApiBehaviourModel.load(ROOT / "specimen" / "data")  # parity of the shipped (rounded) JSON model
    ref = lr.predict_proba(X)[:, 1]
    mine = np.asarray([shipped.proba(r[2]) for r in rows])
    parity = float(np.abs(ref - mine).max())
    print(f"shipped JSON max |diff| vs a scikit-learn refit over all rows: {parity:.2e}")
    published = [{"model": "MalDetConv CNN-BiGRU (Maniriho et al. 2022)", "accuracy": 0.961, "f1": 0.9602,
                  "source": "arXiv:2209.03547v1, Table 3 (p. 19) and Table 5 (p. 19)"},
                 {"model": "MalDy TF-IDF + XGBoost (as reported there)", "accuracy": 0.9559, "f1": "-",
                  "source": "arXiv:2209.03547v1, Table 7 (p. 21)"}]
    write_result("behaviour_malbehavd", {
        "dataset": {"name": "MalbehavD-V1", "samples": int(len(y)), "malicious": int(y.sum()),
                    "split": "70/30 stratified (seed 0, bootstrap 95% CI) + 5 seeds x 70/30 + 5 seeds x 5-fold CV"},
        "holdout": holdout, "seeds_70_30": seeds, "cv": cv, "published": published,
        "dedup_70_30": dedup, "duplicate_leakage": leakage, "pipeline_path": pipeline_path,
        "shipped_model_max_abs_diff_vs_sklearn": parity,
        "ci_method": "Nadeau-Bengio corrected resampled t (repeated splits/folds); percentile bootstrap (seed-0 holdout)",
        "markdown": md_table(holdout + published, ["model", "roc_auc", "roc_auc_95ci", "accuracy", "accuracy_95ci", "f1"]),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
