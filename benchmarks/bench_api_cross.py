"""More API-call datasets: cross-dataset transfer and a Mal-API-2019 paper reproduction.

    SPECIMEN_DATA=... python benchmarks/bench_api_cross.py [--seeds 5]

1. **Cross-dataset** - the *shipped* behaviour scorer (trained on MalbehavD-V1,
   Cuckoo API names) applied unchanged to Mal-API-2019 (Catak et al. 2020,
   7,107 Cuckoo API-call sequences, malware only): detection rate at the
   pipeline thresholds (0.5 suspicious, 0.8 malicious) with Wilson CIs, for
   the first 100 / 1,000 calls and the whole sequence.
2. **Reproduction of Li et al. 2024** (IJCSIT 2(1), doi:10.62051/ijcsit.v2n1.01,
   Table I): 8-class family classification on Mal-API-2019 with TF-IDF (+PCA)
   and Random Forest / XGBoost / KNN / MLP, 5-fold CV. Grid-search ranges and
   the PCA size are not given, so defaults and 100 components are used and
   recorded. SPECIMEN's API uni+bigram TF-IDF + LR runs on the same folds.
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
from common import md_table, mean_ci_nb, wilson, write_result
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

PAPER_LI2024 = {"random-forest": 0.68, "xgboost": 0.68, "knn": 0.54, "mlp": 0.56}


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
                         "detection_rate": round(k / len(s), 4), "wilson_95ci": list(wilson(k, len(s)))})
    return rows, round(overlap, 4)


def _proba_counts(model: ApiBehaviourModel, c: Counter) -> float:
    """Shipped model on a whole sequence given as n-gram counts (same maths as ``ApiBehaviourModel.proba``)."""
    import math
    v = {t: (1 + math.log(n)) * model.idf[t] for t, n in c.items() if t in model.idf}
    norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
    z = model.intercept + sum(x / norm * model.weight.get(t, 0.0) for t, x in v.items())
    return 1 / (1 + math.exp(-max(min(z, 30), -30)))


def li2024(X_uni: sparse.csr_matrix, X_bi: sparse.csr_matrix, y: np.ndarray, pool: np.ndarray, seeds: int) -> list[dict]:
    from xgboost import XGBClassifier
    models = {
        "random-forest": lambda s: RandomForestClassifier(n_estimators=300, n_jobs=4, random_state=s),
        "xgboost": lambda s: XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, n_jobs=4,
                                           random_state=s, tree_method="hist"),
        "knn": lambda s: KNeighborsClassifier(n_neighbors=5),
        "mlp": lambda s: MLPClassifier(hidden_layer_sizes=(128,), max_iter=300, random_state=s),
    }
    acc: dict[str, list[float]] = {m: [] for m in [*models, "specimen-lr (uni+bigram)"]}
    for sd in range(seeds):
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=sd).split(pool, y[pool]):
            tr, te = pool[tr], pool[te]
            tf = TfidfTransformer(sublinear_tf=True).fit(X_uni[tr])
            svd = TruncatedSVD(100, random_state=sd).fit(tf.transform(X_uni[tr]))  # "PCA" on sparse TF-IDF
            Ztr, Zte = svd.transform(tf.transform(X_uni[tr])), svd.transform(tf.transform(X_uni[te]))
            for name, mk in models.items():
                m = mk(sd).fit(Ztr, y[tr])
                acc[name].append(float((m.predict(Zte) == y[te]).mean()))
            tb = TfidfTransformer(sublinear_tf=True).fit(X_bi[tr])
            lr = LogisticRegression(C=10, max_iter=3000).fit(tb.transform(X_bi[tr]), y[tr])
            acc["specimen-lr (uni+bigram)"].append(float((lr.predict(tb.transform(X_bi[te])) == y[te]).mean()))
        print(f"  seed {sd}: " + ", ".join(f"{k}={np.mean(v):.3f}" for k, v in acc.items()), flush=True)
    n = len(pool)
    return [{"model": k, "paper_table1": PAPER_LI2024.get(k, "-"),
             "accuracy": mean_ci_nb(v, n * 4 // 5, n // 5), "runs": [round(x, 4) for x in v]} for k, v in acc.items()]


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
            "accuracy": mean_ci_nb(accs, n * 4 // 5, n // 5), "balanced_accuracy": mean_ci_nb(bal, n * 4 // 5, n // 5),
            "roc_auc": mean_ci_nb(aucs, n * 4 // 5, n // 5)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args()
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
    li_rows = [{"protocol": p, **r} for p, rs in out.items() for r in rs]
    write_result("api_cross", {
        "malapi": {"rows": len(y), "distinct_sequences": len(first), "classes": sorted(set(labels)),
                   "median_calls": int(np.median(lens)), "max_calls": int(max(lens)),
                   "source": "github.com/ocatak/malware_api_class (MIT)"},
        "cross_dataset_malbehavd_to_malapi": {"model": "shipped specimen/data/api_behaviour.json (MalbehavD-V1)",
                                              "call_vocabulary_overlap": overlap, "rows": cross},
        "repro_li2024": {"paper": "Li et al. 2024, IJCSIT 2(1), Table I (5-fold CV, grid-searched)",
                         "unspecified_choices": "TruncatedSVD(100) for PCA; default hyperparameters "
                                                "(RF/XGB 300 trees, KNN k=5, MLP 128 hidden); unigram TF-IDF",
                         "rows": li_rows},
        "oliveira_within_dataset": oli,
        "ci_method": "Wilson (detection rates); Nadeau-Bengio corrected t over folds x seeds",
        "markdown": md_table(cross, ["input", "threshold", "detection_rate", "wilson_95ci"]) + "\n\n"
        + md_table(li_rows, ["protocol", "model", "paper_table1", "accuracy"]),
    })
    print(f"done in {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
