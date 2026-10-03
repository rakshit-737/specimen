"""More API-call datasets: cross-dataset transfer and a Mal-API-2019 paper reproduction.

    SPECIMEN_DATA=... python benchmarks/bench_api_cross.py [--seeds 5]

1. **Cross-dataset** - the *shipped* behaviour scorer (trained on MalbehavD-V1,
   Cuckoo API names) applied unchanged to Mal-API-2019 (Catak et al. 2020,
   7,107 Cuckoo API-call sequences, malware only): detection rate at the
   pipeline thresholds (0.5 suspicious, 0.8 malicious) with Wilson CIs, for
   the first 100 / 1,000 calls and the whole sequence.
2. **Reproduction of Li et al. 2024** (IJCSIT 2(1), doi:10.62051/ijcsit.v2n1.01,
   Table I on p. 6): 8-class family classification on Mal-API-2019, 5-fold CV.
   The paper reports TF-IDF models (KNN 0.54, RF 0.68, XGBoost 0.68, a 4-layer
   ReLU+dropout network 0.56) and TF-IDF + PCA models (KNN 0.54, RF 0.62,
   XGBoost 0.62). Re-implemented here on the same feature sets: unigram
   TF-IDF, and unigram TF-IDF + TruncatedSVD(100) (sparse "PCA"; the size is
   not stated). The paper grid-searches hyperparameters (section 5.1, p. 6)
   without giving the ranges, so **no grid search is run**: defaults are used
   and recorded, which may explain part of any gap. The 4-layer network uses
   hidden sizes 256-128-64-32 (not stated) and scikit-learn's MLP (L2 instead
   of dropout).
   **Feature-matched comparison**: SPECIMEN's logistic regression on the same
   unigram TF-IDF (with and without SVD), and a random forest on SPECIMEN's
   uni+bigram TF-IDF, all on the same folds, so each pair differs only in the
   model (XGBoost on the ~10^4 uni+bigram columns is left out for run time); differences get a Nadeau-Bengio corrected paired t-test.
   Reported under the paper protocol (all rows) and a duplicate-free
   protocol (one row per distinct sequence).
3. **Oliveira (2019)** API-call sequences (integer-coded, first 100 calls,
   42,797 malware / 1,079 goodware): the API-name table is not published with
   the re-hosted CSV, so no cross-dataset transfer is possible; SPECIMEN's
   n-gram LR is evaluated within the dataset (5-fold, duplicate-free).

The 2.17 GB Mal-API text file is streamed from the zip one line at a time;
only per-sequence token counts are kept (peak RSS < 1.5 GB).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import time
import zipfile
from collections import Counter

import numpy as np
from common import corrected_paired_t, nb_interval, require_data, wilson, write_result
from scipy import sparse
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier

from specimen.api_behaviour import ApiBehaviourModel, ngrams
from specimen.datasets import data_root
from specimen.pipeline import PACKAGED_MODELS

# Li et al. 2024, Table I (p. 6): average accuracy over 5-fold CV
PAPER_LI2024 = {("random-forest", "tfidf"): 0.68, ("xgboost", "tfidf"): 0.68, ("knn", "tfidf"): 0.54,
                ("nn-4-layer", "tfidf"): 0.56, ("knn", "tfidf+pca"): 0.54, ("random-forest", "tfidf+pca"): 0.62,
                ("xgboost", "tfidf+pca"): 0.62}
FEATURES = {"tfidf": "unigram TF-IDF (paper features)",
            "tfidf+pca": "unigram TF-IDF + TruncatedSVD(100) (paper's PCA; size not stated)",
            "uni+bigram": "uni+bigram TF-IDF (SPECIMEN features)"}


def stream_malapi(cuts: tuple[int, ...] = (100, 1000)):
    """Yield (label, unigram Counter, bigram-doc tokens, prefixes) per Mal-API-2019 row."""
    root = data_root() / "malapi"
    labels = [ln.strip() for ln in (root / "labels.csv").read_text().splitlines() if ln.strip()]
    with zipfile.ZipFile(root / "mal-api-2019.zip") as z, z.open("all_analysis_data.txt") as raw:
        for lab, line in zip(labels, io.TextIOWrapper(raw, encoding="ascii", errors="replace")):
            calls = line.split()
            yield lab, calls[: max(cuts)], len(calls), Counter(calls), Counter(ngrams(calls)), \
                hashlib.sha256(" ".join(calls).encode()).hexdigest()


def cross_dataset(model: ApiBehaviourModel, prefixes: list[list[str]], fulls: list[Counter]) -> list[dict]:
    rows = []
    vocab = {t for t in model.idf if ">" not in t}
    seen_calls = Counter()
    for c in fulls:
        seen_calls.update(c)
    overlap = sum(v for k, v in seen_calls.items() if k in vocab) / max(1, sum(seen_calls.values()))
    for name, scores in (("first 100 calls", [model.proba(p[:100]) for p in prefixes]),
                         ("first 1,000 calls", [model.proba(p[:1000]) for p in prefixes]),
                         ("whole sequence", [_proba_counts(model, c) for c in fulls])):
        s = np.asarray(scores)
        for thr in (0.5, 0.8):
            k = int((s >= thr).sum())
            rows.append({"input": name, "threshold": thr, "detected": k, "n": len(s),
                         "detection_rate": k / len(s), "wilson_95ci": list(wilson(k, len(s)))})
    return rows, round(overlap, 4)


def _proba_counts(model: ApiBehaviourModel, c: Counter) -> float:
    """Shipped model on a whole sequence given as n-gram counts (same maths as ``ApiBehaviourModel.proba``)."""
    import math
    v = {t: (1 + math.log(n)) * model.idf[t] for t, n in c.items() if t in model.idf}
    norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
    z = model.intercept + sum(x / norm * model.weight.get(t, 0.0) for t, x in v.items())
    return 1 / (1 + math.exp(-max(min(z, 30), -30)))


def _models():
    from xgboost import XGBClassifier
    return {
        "random-forest": lambda s: RandomForestClassifier(n_estimators=300, n_jobs=4, random_state=s),
        "xgboost": lambda s: XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, n_jobs=4,
                                           random_state=s, tree_method="hist"),
        "knn": lambda s: KNeighborsClassifier(n_neighbors=5),
        "nn-4-layer": lambda s: MLPClassifier(hidden_layer_sizes=(256, 128, 64, 32), max_iter=300,
                                              early_stopping=True, random_state=s),
        "specimen-lr": lambda s: LogisticRegression(C=10, max_iter=3000),
    }


# (model, features) pairs evaluated on every fold
GRID = [("random-forest", "tfidf"), ("xgboost", "tfidf"), ("knn", "tfidf"), ("nn-4-layer", "tfidf"),
        ("knn", "tfidf+pca"), ("random-forest", "tfidf+pca"), ("xgboost", "tfidf+pca"),
        ("specimen-lr", "tfidf"), ("specimen-lr", "tfidf+pca"), ("specimen-lr", "uni+bigram"),
        ("random-forest", "uni+bigram")]
PAIRS = [(("random-forest", "tfidf"), ("specimen-lr", "tfidf")), (("xgboost", "tfidf"), ("specimen-lr", "tfidf")),
         (("random-forest", "tfidf+pca"), ("specimen-lr", "tfidf+pca")),
         (("random-forest", "uni+bigram"), ("specimen-lr", "uni+bigram")),
         (("specimen-lr", "tfidf"), ("specimen-lr", "uni+bigram"))]


def li2024(X_uni: sparse.csr_matrix, X_bi: sparse.csr_matrix, y: np.ndarray, pool: np.ndarray, seeds: int) -> dict:
    """Paper rows and feature-matched rows on identical folds, with corrected paired tests."""
    models = _models()
    acc: dict[tuple[str, str], list[float]] = {g: [] for g in GRID}
    for sd in range(seeds):
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=sd).split(pool, y[pool]):
            tr, te = pool[tr], pool[te]
            tf = TfidfTransformer(sublinear_tf=True).fit(X_uni[tr])
            U_tr, U_te = tf.transform(X_uni[tr]), tf.transform(X_uni[te])
            svd = TruncatedSVD(100, random_state=sd).fit(U_tr)  # "PCA" on sparse TF-IDF
            tb = TfidfTransformer(sublinear_tf=True).fit(X_bi[tr])
            feats = {"tfidf": (U_tr, U_te), "tfidf+pca": (svd.transform(U_tr), svd.transform(U_te)),
                     "uni+bigram": (tb.transform(X_bi[tr]), tb.transform(X_bi[te]))}
            for name, fset in GRID:
                Ztr, Zte = feats[fset]
                if name == "nn-4-layer":  # dense input for the MLP is small (unigram vocabulary)
                    Ztr, Zte = Ztr.toarray(), Zte.toarray()
                m = models[name](sd).fit(Ztr, y[tr])
                acc[(name, fset)].append(float((m.predict(Zte) == y[te]).mean()))
        print(f"  seed {sd}: " + ", ".join(f"{k[0]}/{k[1]}={np.mean(v):.3f}" for k, v in acc.items()), flush=True)
    n = len(pool)
    rows = [{"model": k[0], "features": k[1], "features_text": FEATURES[k[1]],
             "paper_table1": PAPER_LI2024.get(k, None), "accuracy": nb_interval(v, n * 4 // 5, n // 5),
             "runs": v} for k, v in acc.items()]
    tests = [{"a": f"{a[0]} / {a[1]}", "b": f"{b[0]} / {b[1]}",
              **corrected_paired_t(acc[a], acc[b], n * 4 // 5, n // 5)} for a, b in PAIRS]
    for t in tests:
        print(t, flush=True)
    return {"rows": rows, "paired_tests": tests}


def oliveira(seeds: int) -> dict:
    path = data_root() / "oliveira" / "dynamic_api_call_sequence_per_malware_100_0_306.csv"
    docs, y, seen = [], [], set()
    with open(path, newline="") as f:
        r = csv.reader(f)
        next(r)
        n_rows = 0
        for row in r:
            n_rows += 1
            calls = row[1:-1]
            key = " ".join(calls)
            if key in seen:
                continue
            seen.add(key)
            docs.append(Counter(ngrams(calls)))
            y.append(int(row[-1]))
    y = np.asarray(y)
    X = DictVectorizer().fit_transform(docs)
    accs, aucs, bal = [], [], []
    from sklearn.metrics import balanced_accuracy_score, roc_auc_score
    for sd in range(seeds):
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=sd).split(X, y):
            tf = TfidfTransformer(sublinear_tf=True).fit(X[tr])
            m = LogisticRegression(C=10, max_iter=3000, class_weight="balanced").fit(tf.transform(X[tr]), y[tr])
            p = m.predict_proba(tf.transform(X[te]))[:, 1]
            accs.append(float(((p >= 0.5) == y[te]).mean()))
            bal.append(float(balanced_accuracy_score(y[te], p >= 0.5)))
            aucs.append(float(roc_auc_score(y[te], p)))
    n = len(y)
    return {"rows": n_rows, "distinct_sequences": n, "malware": int(y.sum()), "goodware": int((y == 0).sum()),
            "protocol": "duplicate-free, 5-fold stratified CV x seeds, class_weight=balanced",
            "accuracy": nb_interval(accs, n * 4 // 5, n // 5),
            "balanced_accuracy": nb_interval(bal, n * 4 // 5, n // 5),
            "roc_auc": nb_interval(aucs, n * 4 // 5, n // 5)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args()
    require_data("malapi/mal-api-2019.zip", "malapi/labels.csv",
                 "oliveira/dynamic_api_call_sequence_per_malware_100_0_306.csv")
    t0 = time.time()
    model = ApiBehaviourModel.load(PACKAGED_MODELS)
    labels, prefixes, lens, unis, bis, keys = [], [], [], [], [], []
    for lab, pre, n, uni, bi, key in stream_malapi():
        labels.append(lab)
        prefixes.append(pre)
        lens.append(n)
        unis.append(uni)
        bis.append(bi)
        keys.append(key)
    print(f"Mal-API-2019: {len(labels)} rows streamed in {time.time() - t0:.0f}s; median {int(np.median(lens))} calls")
    cross, overlap = cross_dataset(model, prefixes, bis)
    for r in cross:
        print(r)
    y = np.unique(np.asarray(labels), return_inverse=True)[1]  # integer classes (xgboost needs them)
    X_uni = DictVectorizer().fit_transform(unis).tocsr()
    X_bi = DictVectorizer().fit_transform(bis).tocsr()
    del unis, bis
    first: dict[str, int] = {}
    for i, k in enumerate(keys):
        first.setdefault(k, i)
    out = {}
    for pname, pool in (("paper (all rows, 5-fold CV)", np.arange(len(y))),
                        ("dedup (distinct sequences, 5-fold CV)", np.asarray(sorted(first.values())))):
        print(pname)
        out[pname] = li2024(X_uni, X_bi, y, pool, a.seeds)
    oli = oliveira(a.seeds)
    print("oliveira", oli)
    write_result("api_cross", {
        "malapi": {"rows": len(y), "distinct_sequences": len(first), "classes": sorted(set(labels)),
                   "median_calls": int(np.median(lens)), "max_calls": int(max(lens)),
                   "source": "github.com/ocatak/malware_api_class (MIT)"},
        "cross_dataset_malbehavd_to_malapi": {"model": "shipped specimen/data/api_behaviour.json (MalbehavD-V1)",
                                              "call_vocabulary_overlap": overlap, "rows": cross},
        "repro_li2024": {"paper": "Li Z., Zhu H., Liu H., Song J., Cheng Q. Comprehensive evaluation of Mal-API-2019 "
                                  "dataset by machine learning in malware detection. IJCSIT 2(1), 2024, "
                                  "doi:10.62051/ijcsit.v2n1.01; Table I, p. 6",
                         "unspecified_choices": "no grid search (ranges not given; paper section 5.1, p. 6); "
                                                "TruncatedSVD(100) for PCA; RF/XGB 300 trees, KNN k=5; 4-layer NN "
                                                "hidden sizes 256-128-64-32 with L2 instead of dropout",
                         "features": FEATURES,
                         "protocols": {p: v for p, v in out.items()}},
        "oliveira_within_dataset": oli,
        "ci_method": "Wilson (detection rates); Nadeau-Bengio corrected t over folds x seeds (logit scale near 0/1); "
                     "corrected paired t for model comparisons on the same folds",
    })
    print(f"done in {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
