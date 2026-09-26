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
from common import ROOT, binary_metrics, bootstrap_ci, md_table, mean_ci, write_result
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split

from specimen.adapters.api_seq import api_sequence_to_trace
from specimen.api_behaviour import ApiBehaviourModel, ngrams
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
        holdout.append({"model": n, **m, "accuracy_95ci": f"[{lo}, {hi}]", "roc_auc_95ci": f"[{alo}, {ahi}]"})
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
        seeds.append({"model": n, "accuracy": mean_ci(accs), "roc_auc": mean_ci(aucs), "f1": mean_ci(f1s)})
        print(seeds[-1])
        accs, aucs = [], []
        for sd in SEEDS:
            for ftr, fte in StratifiedKFold(5, shuffle=True, random_state=sd).split(idx, y):
                m = binary_metrics(y[fte], fit_predict(n, ftr, fte, docs, F, y, mvp))
                accs.append(m["accuracy"])
                aucs.append(m["roc_auc"])
        cv.append({"model": n, "cv_accuracy": mean_ci(accs), "cv_roc_auc": mean_ci(aucs)})
        print(cv[-1])
    # ship the pipeline scorer: TF-IDF + LR on all rows, exported as pure-Python JSON
    vec = TfidfVectorizer(analyzer=lambda d: d, min_df=2, sublinear_tf=True)
    X = vec.fit_transform(docs)
    lr = LogisticRegression(C=10, max_iter=3000).fit(X, y)
    vocab = vec.get_feature_names_out()
    model = ApiBehaviourModel(dict(zip(vocab, vec.idf_.astype(float))), dict(zip(vocab, lr.coef_[0].astype(float))),
                              float(lr.intercept_[0]), {"trained_on": "MalbehavD-V1", "n_train": int(len(y)),
                                                        "features": "API uni+bigram sublinear TF-IDF", "C": 10})
    model.save(ROOT / "models")
    ref = lr.predict_proba(X[:200])[:, 1]
    mine = np.asarray([model.proba(rows[i][2]) for i in range(200)])
    print(f"pure-Python export max |diff| vs sklearn: {np.abs(ref - mine).max():.2e}")
    published = [{"model": "MalDetConv CNN-BiGRU (Maniriho et al. 2022)", "accuracy": 0.961, "f1": 0.9602},
                 {"model": "MalDy TF-IDF + XGBoost (as reported there)", "accuracy": 0.9559, "f1": "-"}]
    write_result("behaviour_malbehavd", {
        "dataset": {"name": "MalbehavD-V1", "samples": int(len(y)), "malicious": int(y.sum()),
                    "split": "70/30 stratified (seed 0, bootstrap 95% CI) + 5 seeds x 70/30 + 5 seeds x 5-fold CV"},
        "holdout": holdout, "seeds_70_30": seeds, "cv": cv, "published": published,
        "markdown": md_table(holdout + published, ["model", "roc_auc", "roc_auc_95ci", "accuracy", "accuracy_95ci", "f1"])
        + "\n\n" + md_table(seeds, ["model", "accuracy", "roc_auc", "f1"])
        + "\n\n" + md_table(cv, ["model", "cv_accuracy", "cv_roc_auc"]),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
