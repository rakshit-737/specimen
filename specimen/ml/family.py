"""Behaviour-family model over normalised trace tokens.

A hashed bag-of-tokens + multinomial logistic regression. Linear on
human-readable tokens, so every prediction decomposes into per-token
contributions (``explain``). Weights are stored as a plain ``.npz`` (no
pickle) and can be loaded by the pipeline at analysis time.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np
from scipy import sparse
from sklearn.feature_extraction import FeatureHasher
from sklearn.linear_model import LogisticRegression

N_FEATURES = 2 ** 18
_HASHER = FeatureHasher(N_FEATURES, input_type="string", alternate_sign=False)


def hash_tokens(docs: Sequence[Sequence[str]]) -> sparse.csr_matrix:
    X = _HASHER.transform(docs).tocsr()
    X.data[:] = 1.0
    # L2-normalise so long reports do not dominate
    norms = np.sqrt(np.asarray(X.multiply(X).sum(axis=1)).ravel())
    norms[norms == 0] = 1.0
    return sparse.diags(1.0 / norms) @ X


class FamilyModel:
    def __init__(self, coef: np.ndarray, intercept: np.ndarray, classes: list[str],
                 meta: dict[str, Any] | None = None) -> None:
        self.coef = coef
        self.intercept = intercept
        self.classes = classes
        self.meta = meta or {}

    @property
    def uses_static(self) -> bool:
        """Whether the model was trained on static.pe tokens as well."""
        return "static" in self.meta.get("tokens", ["behaviour", "static"])

    @classmethod
    def fit(cls, docs: Sequence[Sequence[str]], labels: Sequence[str], C: float = 10.0,
            max_iter: int = 300) -> FamilyModel:
        """Fit hashed-token multinomial logistic regression.

        :param docs: token lists (behaviour and/or static tokens).
        :param labels: family names.
        :param C: inverse regularisation strength.
        :param max_iter: lbfgs iterations.
        """
        X = hash_tokens(docs)
        lr = LogisticRegression(C=C, max_iter=max_iter, solver="lbfgs")
        lr.fit(X, list(labels))
        coef, icpt = lr.coef_, lr.intercept_
        if coef.shape[0] == 1:  # binary: softmax([0, z]) == sigmoid(z)
            coef = np.vstack([np.zeros_like(coef), coef])
            icpt = np.concatenate([[0.0], icpt])
        return cls(coef.astype(np.float32), icpt.astype(np.float32), [str(c) for c in lr.classes_])

    def proba(self, docs: Sequence[Sequence[str]]) -> np.ndarray:
        z = np.asarray(hash_tokens(docs) @ self.coef.T) + self.intercept
        z -= z.max(axis=1, keepdims=True)
        e = np.exp(z)
        return e / e.sum(axis=1, keepdims=True)

    def predict(self, docs: Sequence[Sequence[str]]) -> list[str]:
        return [self.classes[i] for i in self.proba(docs).argmax(axis=1)]

    def explain(self, tokens: Sequence[str], family: str, k: int = 8) -> list[tuple[str, float]]:
        ci = self.classes.index(family)
        uniq = sorted(set(tokens))
        if not uniq:
            return []
        w = 1.0 / np.sqrt(len(uniq))
        idx = hash_tokens([[t] for t in uniq]).indices if uniq else []
        contrib = [(t, float(self.coef[ci, j]) * w) for t, j in zip(uniq, idx)]
        contrib.sort(key=lambda c: -c[1])
        return [(t, round(c, 4)) for t, c in contrib[:k]]

    def save(self, path: Path, meta: dict[str, Any] | None = None) -> None:
        path.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(path / "family_model.npz", coef=self.coef, intercept=self.intercept,
                            classes=np.asarray(self.classes, dtype=str))
        (path / "family_meta.json").write_text(json.dumps(meta or {}, indent=2))

    @classmethod
    def load(cls, path: Path) -> FamilyModel:
        d = np.load(path / "family_model.npz")  # numeric/unicode arrays only, no pickle
        mp = path / "family_meta.json"
        meta = json.loads(mp.read_text()) if mp.exists() else {}
        return cls(d["coef"], d["intercept"], [str(c) for c in d["classes"]], meta)
