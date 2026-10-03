"""Behavior ML scoring: pure-Python logistic regression over explainable
features, per-event rarity (anomaly), and nearest-family clustering."""
from __future__ import annotations

import math
from collections import Counter
from functools import lru_cache

from .corpus import synthetic_corpus
from .models import BehaviorScore, Contribution, Trace
from .provenance import map_technique

FEATURES = [
    "n_inject", "n_persist", "n_impact", "n_exec_script", "n_c2", "n_drop",
    "n_file_write", "n_delete", "frac_suspicious",
]


def featurize(trace: Trace) -> list[float]:
    """MVP behaviour features: nine log-scaled ATT&CK-derived counts of a trace.

    :param trace: validated trace.
    :returns: feature vector in the order of ``FEATURES``.
    """
    c: Counter[str] = Counter()
    susp = 0
    for ev in trace.events:
        tech, tactic = map_technique(ev)
        if ev.type == "process_inject":
            c["n_inject"] += 1
        if tactic == "persistence":
            c["n_persist"] += 1
        if tactic == "impact":
            c["n_impact"] += 1
        if tech == "T1059.001":
            c["n_exec_script"] += 1
        if tactic == "command-and-control" and ev.type != "file_write":
            c["n_c2"] += 1
        if tech == "T1105":
            c["n_drop"] += 1
        if ev.type == "file_write":
            c["n_file_write"] += 1
        if ev.type == "file_delete":
            c["n_delete"] += 1
        if tactic in ("persistence", "impact", "defense-evasion", "execution"):
            susp += 1
    vec = [math.log1p(c[f]) for f in FEATURES[:-1]]
    vec.append(susp / max(len(trace.events), 1))
    return vec


def technique_set(trace: Trace) -> frozenset[str]:
    """ATT&CK techniques present in a trace."""
    return frozenset(t for ev in trace.events if (t := map_technique(ev)[0]))


class LogisticModel:
    """Tiny pure-Python logistic regression (the MVP scorer, trained on synthetic traces)."""
    def __init__(self, n: int) -> None:
        self.w = [0.0] * n
        self.b = 0.0

    def predict(self, x: list[float]) -> float:
        """Probability for one feature vector."""
        z = self.b + sum(wi * xi for wi, xi in zip(self.w, x))
        z = max(min(z, 30), -30)
        return 1 / (1 + math.exp(-z))

    def fit(self, X: list[list[float]], y: list[int], lr: float = 0.3,
            epochs: int = 400, l2: float = 0.01) -> LogisticModel:
        """Full-batch gradient descent with L2 regularisation; returns ``self``."""
        n = len(X)
        for _ in range(epochs):
            gw = [0.0] * len(self.w)
            gb = 0.0
            for x, t in zip(X, y):
                err = self.predict(x) - t
                gb += err
                for j, xj in enumerate(x):
                    gw[j] += err * xj
            self.b -= lr * gb / n
            self.w = [w - lr * (g / n + l2 * w) for w, g in zip(self.w, gw)]
        return self


@lru_cache(maxsize=1)
def trained() -> tuple[LogisticModel, dict[str, list[frozenset[str]]], Counter]:
    """The MVP scorer trained on the synthetic corpus, the family prototypes and technique frequencies (cached)."""
    corpus = synthetic_corpus()
    X = [featurize(t) for t, _, _ in corpus]
    y = [lab for _, lab, _ in corpus]
    model = LogisticModel(len(FEATURES)).fit(X, y)
    protos: dict[str, list[frozenset[str]]] = {}
    for t, _, fam in corpus:
        if fam:
            protos.setdefault(fam, []).append(technique_set(t))
    benign_freq: Counter = Counter()
    for t, lab, _ in corpus:
        if lab == 0:
            benign_freq.update(ev.type for ev in t.events)
    return model, protos, benign_freq


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    """Jaccard similarity of two technique sets (0 when both are empty)."""
    return len(a & b) / len(a | b) if a | b else 0.0


def event_anomaly(event_type: str, technique: str | None) -> float:
    """Rarity of this action vs. the benign baseline (0 common .. 1 never seen)."""
    _, _, freq = trained()
    total = sum(freq.values()) or 1
    base = 1.0 - min(freq.get(event_type, 0) / total * 4, 1.0)
    return round(min(1.0, base + (0.3 if technique else 0.0)), 3)


def score(trace: Trace, family_threshold: float = 0.5) -> BehaviorScore:
    """Score a trace with the MVP synthetic-trained scorer and the Jaccard family matcher.

    :param trace: validated trace.
    :param family_threshold: minimum Jaccard similarity for a family match.
    :returns: probability, label, per-feature contributions and family match.
    """
    model, protos, _ = trained()
    x = featurize(trace)
    p = model.predict(x)
    contribs = sorted((Contribution(f, round(v, 4), round(w, 4)) for f, v, w in zip(FEATURES, x, model.w) if v),
                      key=lambda c: -abs(c.impact))
    label = "malicious" if p >= 0.8 else "suspicious" if p >= 0.5 else "benign"
    ts = technique_set(trace)
    best, sim = None, 0.0
    for fam, sets in protos.items():
        s = max(jaccard(ts, x2) for x2 in sets)
        if s > sim:
            best, sim = fam, s
    if sim < family_threshold or label == "benign":
        best = None
    return BehaviorScore(round(p, 4), label, contribs, best, round(sim, 3))
