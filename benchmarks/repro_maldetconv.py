"""Reproduction of MalDetConv (Maniriho, Mahmood, Chowdhury; arXiv:2209.03547v1, 2022) on MalbehavD-V1.

    SPECIMEN_DATA=... python benchmarks/repro_maldetconv.py [--seeds 10] [--epochs 20]

Page numbers refer to arXiv:2209.03547v1.

Stated in the paper and used here:

* integer encoding of API names, zero padding to a fixed length n in
  {20, 40, 60, 80, 100} (section 4.4, p. 15; Fig. 10 A-2, p. 17);
* embedding ``output_dim`` 100 ("we have set the output_dim value to 100",
  p. 15; "Embedding Dimension: 100", Fig. 10 A-2, p. 17);
* Conv1D 128 filters, filter size 8, ReLU, dropout 0.2 -> max pooling ->
  Conv1D 64 filters, kernel 5, ReLU -> max pooling -> BiGRU 120 units
  (sigmoid recurrent activation, tanh) -> flatten -> dense 150 / 100 / 60
  (ReLU, dropout 0.2 each) -> dense 15 (ReLU) -> 1 sigmoid output
  (Fig. 10 A-2, p. 17; dropout 0.2 also in section 4.5.4, p. 16);
* Adam with learning rate 0.001 and binary cross-entropy (p. 16; Fig. 10 A-2);
* random 70/30 split (section 5.2, p. 18); test accuracy per n in Table 3 (p. 19).

Not stated, so Keras defaults or guesses (recorded in the result file):
pool size 2 and ``padding='valid'`` (Keras defaults), batch size 32 (Keras
``fit`` default), 20 epochs, Keras ``Tokenizer`` behaviour (lower-cased,
unknown calls dropped, fitted on the training split) and ``pad_sequences``
defaults (``padding='pre'``, ``truncating='pre'``: the last n calls are kept).

The round-3 configuration (embedding 10, two Conv1D blocks of 64 filters
with kernel 3, BiGRU 64, one dense layer of 64), which wrongly treated the
layer sizes as unstated, is kept as an ablation row.

SPECIMEN's API n-gram LR is trained on exactly the same truncated sequences
and splits; LR minus reproduction gets a Nadeau-Bengio corrected paired t-test.

Protocols: the paper's random split over all rows, and a duplicate-free split
in which the *model input* is unique: for each n, rows are grouped by their
last n calls (what the network sees) and one row per group is kept; groups
whose rows carry both labels are dropped. CPU only, < 2 GB RAM.
"""
from __future__ import annotations

import argparse
import time
from collections import defaultdict

import numpy as np
from common import corrected_paired_t, nb_interval, require_data, write_result
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from specimen.api_behaviour import ngrams
from specimen.datasets import iter_malbehavd

LENGTHS = [20, 40, 60, 80, 100]
PAPER_TABLE3 = {20: 0.9377, 40: 0.9403, 60: 0.9519, 80: 0.9545, 100: 0.9610}
SOURCE = {"table3": "arXiv:2209.03547v1, Table 3, p. 19",
          "embedding_dim": "p. 15 (section 4.4) and Fig. 10 A-2, p. 17",
          "layers": "Fig. 10 A-2, p. 17", "dropout": "section 4.5.4, p. 16 and Fig. 10 A-2",
          "optimizer_loss": "p. 16 and Fig. 10 A-2", "split": "section 5.2, p. 18"}
ARCHS = {
    "paper (Fig. 10 A-2)": {"embedding_dim": 100, "convs": [(128, 8, 0.2), (64, 5, 0.0)], "pool": 2,
                            "conv_padding": "valid", "gru_units": 120, "dense": [(150, 0.2), (100, 0.2), (60, 0.2),
                                                                                 (15, 0.0)]},
    "round-3 guess (ablation)": {"embedding_dim": 10, "convs": [(64, 3, 0.0), (64, 3, 0.0)], "pool": 2,
                                 "conv_padding": "same", "gru_units": 64, "dense": [(64, 0.2)]},
}
TRAINING = {"optimizer": "Adam", "lr": 1e-3, "batch": 32, "loss": "binary cross-entropy",
            "padding": "pre (Keras default)", "truncating": "pre (Keras default)", "tokenizer_fit": "train split",
            "stated": ["embedding_dim", "filters", "kernel sizes", "dropout", "GRU units", "dense sizes", "Adam lr",
                       "loss", "70/30 split"],
            "guessed": ["pool size 2 (Keras default)", "conv padding valid (Keras default)",
                        "batch 32 (Keras default)", "epochs"]}


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


def build(vocab: int, n: int, arch: dict):
    import torch
    from torch import nn

    class MalDetConv(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.emb = nn.Embedding(vocab + 1, arch["embedding_dim"], padding_idx=0)
            layers, ch, steps = [], arch["embedding_dim"], n
            for filters, k, drop in arch["convs"]:
                layers += [nn.Conv1d(ch, filters, k, padding=arch["conv_padding"]), nn.ReLU()]
                if drop:
                    layers.append(nn.Dropout(drop))
                layers.append(nn.MaxPool1d(arch["pool"]))
                ch = filters
                steps = (steps - (k - 1 if arch["conv_padding"] == "valid" else 0)) // arch["pool"]
            if steps < 1:
                raise ValueError(f"sequence length {n} too short for the architecture")
            self.cnn = nn.Sequential(*layers)
            self.gru = nn.GRU(ch, arch["gru_units"], batch_first=True, bidirectional=True)
            head: list = [nn.Flatten()]
            width = steps * 2 * arch["gru_units"]
            for units, drop in arch["dense"]:
                head += [nn.Linear(width, units), nn.ReLU()]
                if drop:
                    head.append(nn.Dropout(drop))
                width = units
            head.append(nn.Linear(width, 1))
            self.head = nn.Sequential(*head)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            h = self.cnn(self.emb(x).transpose(1, 2)).transpose(1, 2)
            out, _ = self.gru(h)
            return self.head(out).squeeze(-1)

    return MalDetConv()


def train_eval(X: np.ndarray, y: np.ndarray, tr: np.ndarray, te: np.ndarray, n: int, seed: int,
               epochs: int, arch: dict) -> float:
    import torch
    torch.manual_seed(seed)
    model = build(int(X.max()), n, arch)
    opt = torch.optim.Adam(model.parameters(), lr=TRAINING["lr"])
    lossf = torch.nn.BCEWithLogitsLoss()
    Xt, yt = torch.from_numpy(X[tr]), torch.from_numpy(y[tr].astype(np.float32))
    g = torch.Generator().manual_seed(seed)
    for _ in range(epochs):
        model.train()
        perm = torch.randperm(len(tr), generator=g)
        for b in range(0, len(tr), TRAINING["batch"]):
            idx = perm[b:b + TRAINING["batch"]]
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


def dedup_pool(seqs: list[list[str]], y: np.ndarray, n: int) -> tuple[np.ndarray, dict]:
    """One row per distinct model input (last n calls, lower-cased); drop inputs seen with both labels."""
    groups: dict[tuple, list[int]] = defaultdict(list)
    for i, s in enumerate(seqs):
        groups[tuple(a.lower() for a in s[-n:])].append(i)
    keep, ambiguous = [], 0
    for rows in groups.values():
        if len({int(y[i]) for i in rows}) > 1:
            ambiguous += 1
            continue
        keep.append(rows[0])
    return np.asarray(sorted(keep)), {"rows": int(len(seqs)), "distinct_inputs": len(groups),
                                      "ambiguous_inputs_dropped": ambiguous, "kept": len(keep)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--epochs", type=int, default=20)
    a = ap.parse_args()
    require_data("malbehavd/MalBehavD-V1-dataset.csv")
    import torch
    torch.set_num_threads(4)
    rows = list(iter_malbehavd())
    seqs = [r[2] for r in rows]
    y = np.asarray([r[1] for r in rows])
    out, dedup_stats = [], {}
    t0 = time.time()
    for pname in ("paper (random 70/30, all rows)", "dedup (distinct model inputs, 70/30)"):
        for n in LENGTHS:
            if pname.startswith("paper"):
                pool = np.arange(len(y))
            else:
                pool, dedup_stats[n] = dedup_pool(seqs, y, n)
            nte = int(round(0.3 * len(pool)))
            runs: dict[str, list[float]] = {k: [] for k in ARCHS}
            lr: list[float] = []
            for sd in range(a.seeds):
                tr, te = train_test_split(pool, test_size=0.3, stratify=y[pool], random_state=sd)
                X = encode(seqs, tr, n)
                for name, arch in ARCHS.items():
                    runs[name].append(train_eval(X, y, tr, te, n, sd, a.epochs, arch))
                lr.append(lr_eval(seqs, y, tr, te, n))
            row = {"protocol": pname, "n": n, "pool": int(len(pool)),
                   "paper_table3": PAPER_TABLE3[n] if pname.startswith("paper") else None,
                   "reproduction": {k: nb_interval(v, len(pool) - nte, nte) for k, v in runs.items()},
                   "specimen_lr": nb_interval(lr, len(pool) - nte, nte),
                   "lr_minus_reproduction": corrected_paired_t(runs["paper (Fig. 10 A-2)"], lr, len(pool) - nte, nte),
                   "repro_runs": runs, "lr_runs": lr}
            out.append(row)
            print(f"{time.time() - t0:.0f}s {pname} n={n}: "
                  + ", ".join(f"{k} {row['reproduction'][k]['mean']:.4f}" for k in ARCHS)
                  + f", LR {row['specimen_lr']['mean']:.4f}", flush=True)
    write_result("repro_maldetconv", {
        "paper": "Maniriho P., Mahmood A. N., Chowdhury M. J. M. MalDetConv (arXiv:2209.03547v1, 2022; "
                 "API-MalDetect, JNCA 2023)",
        "paper_sources": SOURCE,
        "dataset": "MalbehavD-V1", "seeds": a.seeds, "epochs": a.epochs, "architectures": ARCHS,
        "training": TRAINING, "dedup": {str(k): v for k, v in dedup_stats.items()},
        "ci_method": "Nadeau-Bengio corrected resampled t over seeds (logit scale near 0/1); corrected paired t",
        "rows": out,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
