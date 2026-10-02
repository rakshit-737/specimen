"""Reproduction of MalDetConv (Maniriho et al. 2022/2023) on MalbehavD-V1.

    SPECIMEN_DATA=... python benchmarks/repro_maldetconv.py [--seeds 10] [--epochs 20]

Setup taken from the paper (arXiv:2209.03547, sections 4.3-4.5, 5.2, Table 3):

* Keras-Tokenizer-style integer encoding of API names, zero padding to a fixed
  length n in {20, 40, 60, 80, 100} (Keras ``pad_sequences`` defaults:
  ``padding='pre'``, ``truncating='pre'``, i.e. the last n calls are kept);
* embedding (output dim 10, as stated), 1-D CNN with max pooling, BiGRU,
  flatten, fully connected ReLU layer with dropout 0.2, sigmoid output;
* binary cross-entropy, Adam, random 70/30 split.

Not stated in the text (the layer table is only an image, Fig. 10 A-2), so
chosen here and recorded in the result file: two Conv1D blocks with 64
filters, kernel 3, pool 2; BiGRU 64 units per direction; dense 64; Adam lr
1e-3; batch 32; 20 epochs; the tokenizer is fitted on the training split only.

SPECIMEN's API n-gram LR is trained on exactly the same truncated sequences
and the same splits. Both protocols are run: the paper's random split over
all rows, and a duplicate-free split (one row per distinct full sequence).
CPU only, < 1 GB RAM, a few minutes.
"""
from __future__ import annotations

import argparse
import hashlib
import time

import numpy as np
from common import md_table, mean_ci_nb, write_result
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from specimen.api_behaviour import ngrams
from specimen.datasets import iter_malbehavd

LENGTHS = [20, 40, 60, 80, 100]
PAPER_TABLE3 = {20: 0.9377, 40: 0.9403, 60: 0.9519, 80: 0.9545, 100: 0.9610}
HYPER = {"embedding_dim": 10, "conv_blocks": 2, "filters": 64, "kernel": 3, "pool": 2, "gru_units": 64,
         "dense": 64, "dropout": 0.2, "optimizer": "Adam", "lr": 1e-3, "batch": 32, "loss": "binary cross-entropy",
         "padding": "pre (Keras default)", "truncating": "pre (Keras default)", "tokenizer_fit": "train split"}


def encode(seqs: list[list[str]], tr: np.ndarray, n: int) -> np.ndarray:
    vocab: dict[str, int] = {}
    for i in tr:
        for a in seqs[i]:
            vocab.setdefault(a.lower(), len(vocab) + 1)
    X = np.zeros((len(seqs), n), dtype=np.int64)
    for i, s in enumerate(seqs):
        ids = [vocab[a.lower()] for a in s if a.lower() in vocab][-n:]  # Keras drops OOV words, keeps the tail
        if ids:
            X[i, n - len(ids):] = ids
    return X


def build(vocab: int, n: int):
    import torch
    from torch import nn

    class MalDetConv(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.emb = nn.Embedding(vocab + 1, HYPER["embedding_dim"], padding_idx=0)
            f, k, p = HYPER["filters"], HYPER["kernel"], HYPER["pool"]
            self.cnn = nn.Sequential(nn.Conv1d(HYPER["embedding_dim"], f, k, padding="same"), nn.ReLU(), nn.MaxPool1d(p),
                                     nn.Conv1d(f, f, k, padding="same"), nn.ReLU(), nn.MaxPool1d(p))
            self.gru = nn.GRU(f, HYPER["gru_units"], batch_first=True, bidirectional=True)
            steps = n // p // p
            self.head = nn.Sequential(nn.Flatten(), nn.Linear(steps * 2 * HYPER["gru_units"], HYPER["dense"]),
                                      nn.ReLU(), nn.Dropout(HYPER["dropout"]), nn.Linear(HYPER["dense"], 1))

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            h = self.cnn(self.emb(x).transpose(1, 2)).transpose(1, 2)
            out, _ = self.gru(h)
            return self.head(out).squeeze(-1)

    return MalDetConv()


def train_eval(X: np.ndarray, y: np.ndarray, tr: np.ndarray, te: np.ndarray, n: int, seed: int,
               epochs: int) -> float:
    import torch
    torch.manual_seed(seed)
    model = build(int(X.max()), n)
    opt = torch.optim.Adam(model.parameters(), lr=HYPER["lr"])
    lossf = torch.nn.BCEWithLogitsLoss()
    Xt, yt = torch.from_numpy(X[tr]), torch.from_numpy(y[tr].astype(np.float32))
    g = torch.Generator().manual_seed(seed)
    for _ in range(epochs):
        model.train()
        perm = torch.randperm(len(tr), generator=g)
        for b in range(0, len(tr), HYPER["batch"]):
            idx = perm[b:b + HYPER["batch"]]
            opt.zero_grad()
            lossf(model(Xt[idx]), yt[idx]).backward()
            opt.step()
    model.eval()
    with torch.no_grad():
        p = torch.sigmoid(model(torch.from_numpy(X[te]))).numpy()
    return float(((p >= 0.5) == (y[te] == 1)).mean())


def lr_eval(seqs: list[list[str]], y: np.ndarray, tr: np.ndarray, te: np.ndarray, n: int) -> float:
    docs = [ngrams(s[-n:]) for s in seqs]
    vec = TfidfVectorizer(analyzer=lambda d: d, min_df=2, sublinear_tf=True)
    Xtr = vec.fit_transform([docs[i] for i in tr])
    m = LogisticRegression(C=10, max_iter=3000).fit(Xtr, y[tr])
    return float((m.predict(vec.transform([docs[i] for i in te])) == y[te]).mean())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--epochs", type=int, default=20)
    a = ap.parse_args()
    import torch
    torch.set_num_threads(4)
    rows = list(iter_malbehavd())
    seqs = [r[2] for r in rows]
    y = np.asarray([r[1] for r in rows])
    first: dict[str, int] = {}
    for i, s in enumerate(seqs):
        first.setdefault(hashlib.sha256(" ".join(s).encode()).hexdigest(), i)
    protocols = {"paper (random 70/30, all rows)": np.arange(len(y)),
                 "dedup (distinct sequences, 70/30)": np.asarray(sorted(first.values()))}
    out = []
    t0 = time.time()
    for pname, pool in protocols.items():
        nte = int(round(0.3 * len(pool)))
        for n in LENGTHS:
            dl, lr = [], []
            for sd in range(a.seeds):
                tr, te = train_test_split(pool, test_size=0.3, stratify=y[pool], random_state=sd)
                X = encode(seqs, tr, n)
                dl.append(train_eval(X, y, tr, te, n, sd, a.epochs))
                lr.append(lr_eval(seqs, y, tr, te, n))
            row = {"protocol": pname, "n": n, "paper_table3": PAPER_TABLE3[n] if pname.startswith("paper") else "-",
                   "maldetconv_repro": mean_ci_nb(dl, len(pool) - nte, nte),
                   "specimen_lr": mean_ci_nb(lr, len(pool) - nte, nte),
                   "repro_runs": [round(v, 4) for v in dl], "lr_runs": [round(v, 4) for v in lr]}
            out.append(row)
            print(f"{time.time() - t0:.0f}s", {k: v for k, v in row.items() if not k.endswith("runs")}, flush=True)
    write_result("repro_maldetconv", {
        "paper": "Maniriho, Mahmood, Chowdhury - MalDetConv (arXiv:2209.03547; JNCA 2023), Table 3",
        "dataset": "MalbehavD-V1", "seeds": a.seeds, "epochs": a.epochs, "hyperparameters": HYPER,
        "ci_method": "Nadeau-Bengio corrected resampled t over seeds",
        "rows": out,
        "markdown": md_table(out, ["protocol", "n", "paper_table3", "maldetconv_repro", "specimen_lr"]),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
