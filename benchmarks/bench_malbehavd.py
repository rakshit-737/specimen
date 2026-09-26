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
"""
from __future__ import annotations

import numpy as np
from common import binary_metrics, md_table, write_result
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split

from specimen.adapters.api_seq import api_sequence_to_trace
from specimen.datasets import iter_malbehavd
from specimen.scoring import featurize, score


def ngrams(apis: list[str]) -> list[str]:
    a = [x.lower() for x in apis]
    return a + [f"{x}>{y}" for x, y in zip(a, a[1:])]


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
        m = binary_metrics(y[te], fit_predict(n, tr, te, docs, F, y, mvp))
        holdout.append({"model": n, **m})
        print(holdout[-1])
    cv = []
    skf = StratifiedKFold(5, shuffle=True, random_state=0)
    for n in names:
        accs, aucs = [], []
        for ftr, fte in skf.split(idx, y):
            s = fit_predict(n, ftr, fte, docs, F, y, mvp)
            m = binary_metrics(y[fte], s)
            accs.append(m["accuracy"])
            aucs.append(m["roc_auc"])
        cv.append({"model": n, "cv_accuracy": f"{np.mean(accs):.4f} +/- {np.std(accs):.4f}",
                   "cv_roc_auc": f"{np.mean(aucs):.4f} +/- {np.std(aucs):.4f}"})
        print(cv[-1])
    published = [{"model": "MalDetConv CNN-BiGRU (Maniriho et al. 2022)", "accuracy": 0.961, "f1": 0.9602},
                 {"model": "MalDy TF-IDF + XGBoost (as reported there)", "accuracy": 0.9559, "f1": "-"}]
    write_result("behaviour_malbehavd", {
        "dataset": {"name": "MalbehavD-V1", "samples": int(len(y)), "malicious": int(y.sum()),
                    "split": "70/30 stratified (seed 0) + 5-fold CV"},
        "holdout": holdout, "cv": cv, "published": published,
        "markdown": md_table(holdout + published, ["model", "roc_auc", "accuracy", "precision", "recall", "f1"])
        + "\n\n" + md_table(cv, ["model", "cv_accuracy", "cv_roc_auc"]),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
