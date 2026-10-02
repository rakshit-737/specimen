"""Real-data behaviour scorer: API unigram+bigram TF-IDF + logistic regression.

Trained on MalbehavD-V1 (``benchmarks/bench_malbehavd.py``) and stored as a
plain JSON file (``models/api_behaviour.json``: per-token idf and weight, no
pickle). Prediction is pure Python, so the core pipeline stays stdlib-only.
It replicates scikit-learn's ``TfidfVectorizer(sublinear_tf=True)`` (L2
norm) followed by ``LogisticRegression.decision_function``.

It only applies to traces that carry a real API-call sequence (full CAPE /
Cuckoo call logs or API-sequence datasets); reduced reports fall back to
the MVP scorer.
"""
from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .models import BehaviorScore, Contribution, Trace

# Below this the MVP scorer is used. 5 calls give at least 4 bigrams; on MalbehavD the
# n-gram LR is as accurate on 5-19-call traces as on longer ones (results/behaviour_malbehavd.json).
MIN_CALLS = 5
MODEL_FILE = "api_behaviour.json"


def ngrams(apis: Sequence[str]) -> list[str]:
    """Lower-case API unigrams plus adjacent bigrams (``a>b``), the model's token set.

    :param apis: API call names in call order.
    :returns: unigram tokens followed by bigram tokens.
    """
    a = [x.lower() for x in apis]
    return a + [f"{x}>{y}" for x, y in zip(a, a[1:])]


def api_sequence(trace: Trace) -> list[str]:
    """Ordered API names of a trace (typed CAPE events keep theirs in ``extra['api']``)."""
    out = []
    for e in sorted(trace.events, key=lambda e: e.ts):
        if e.extra.get("resolved_only"):
            continue
        if e.type == "api_call" and e.target:
            out.append(e.target)
        elif e.extra.get("api"):
            out.append(str(e.extra["api"]))
    return out


class ApiBehaviourModel:
    """TF-IDF + logistic-regression API n-gram scorer evaluated in pure Python.

    Exported from scikit-learn by ``benchmarks/bench_malbehavd.py``; stored as JSON
    (``specimen/data/api_behaviour.json``) so the core stays stdlib-only.
    """
    def __init__(self, idf: dict[str, float], weight: dict[str, float], intercept: float,
                 meta: dict[str, Any] | None = None) -> None:
        self.idf, self.weight, self.intercept, self.meta = idf, weight, intercept, meta or {}

    def _vector(self, apis: Sequence[str]) -> dict[str, float]:
        tf = Counter(t for t in ngrams(apis) if t in self.idf)
        v = {t: (1 + math.log(c)) * self.idf[t] for t, c in tf.items()}
        n = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / n for t, x in v.items()}

    def proba(self, apis: Sequence[str]) -> float:
        """Malicious probability of an API sequence.

        :param apis: API names in call order.
        :returns: probability in [0, 1].
        """
        z = self.intercept + sum(x * self.weight.get(t, 0.0) for t, x in self._vector(apis).items())
        return 1 / (1 + math.exp(-max(min(z, 30), -30)))

    def explain(self, apis: Sequence[str], k: int = 8) -> list[Contribution]:
        """Top n-gram contributions to the score of an API sequence.

        :param apis: API names in call order.
        :param k: number of contributions to return.
        :returns: contributions sorted by absolute impact.
        """
        cs = [Contribution(t, round(x, 4), round(self.weight.get(t, 0.0), 4)) for t, x in self._vector(apis).items()]
        return sorted((c for c in cs if c.impact), key=lambda c: -abs(c.impact))[:k]

    def score(self, trace: Trace) -> BehaviorScore | None:
        """Score a trace; ``None`` when it holds fewer than ``MIN_CALLS`` API calls.

        :param trace: normalised sandbox trace.
        :returns: a ``BehaviorScore`` or ``None``.
        """
        apis = api_sequence(trace)
        if len(apis) < MIN_CALLS:
            return None
        p = self.proba(apis)
        label = "malicious" if p >= 0.8 else "suspicious" if p >= 0.5 else "benign"
        return BehaviorScore(round(p, 4), label, self.explain(apis),
                             scorer=f"api-ngram-lr ({self.meta.get('trained_on', 'MalbehavD-V1')})")

    def save(self, path: Path) -> Path:
        """Write the model as JSON into a directory.

        :param path: destination directory (created if missing).
        :returns: the model file written.
        """
        path.mkdir(parents=True, exist_ok=True)
        f = path / MODEL_FILE
        doc = {"meta": self.meta, "intercept": self.intercept,
               "tokens": {t: [round(self.idf[t], 5), round(self.weight.get(t, 0.0), 5)] for t in sorted(self.idf)}}
        f.write_text(json.dumps(doc, separators=(",", ":")) + "\n", encoding="utf-8")
        return f

    @classmethod
    def load(cls, path: Path) -> ApiBehaviourModel:
        """Load a model saved with :meth:`save`.

        :param path: directory holding the model file.
        :returns: the loaded model.
        """
        doc = json.loads((path / MODEL_FILE).read_text(encoding="utf-8"))
        toks = doc["tokens"]
        return cls({t: v[0] for t, v in toks.items()}, {t: v[1] for t, v in toks.items()},
                   float(doc["intercept"]), doc.get("meta"))
