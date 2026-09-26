import re
from pathlib import Path

import pytest

import specimen
from specimen.adapters.api_seq import api_sequence_to_trace
from specimen.api_behaviour import MIN_CALLS, ApiBehaviourModel, api_sequence, ngrams
from specimen.models import Event, Trace

ROOT = Path(__file__).resolve().parents[1]


def test_version_matches_pyproject():
    v = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    assert specimen.__version__ == v


def test_ngrams_and_sequence_extraction():
    assert ngrams(["A", "b"]) == ["a", "b", "a>b"]
    t = Trace("r", "", "cape", [
        Event(0.0, "api_call", 1, "x", target="NtOpenKey"),
        Event(0.1, "registry_set", 1, "x", target=r"HKCU\k", extra={"api": "RegSetValueExW"}),
        Event(0.2, "api_call", 1, "x", target="GetProcAddress", extra={"resolved_only": True}),
        Event(0.3, "file_write", 1, "x", target=r"c:\a"),
    ])
    assert api_sequence(t) == ["NtOpenKey", "RegSetValueExW"]


def test_pure_python_matches_sklearn():
    np = pytest.importorskip("numpy")
    pytest.importorskip("sklearn")
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    rng = np.random.default_rng(0)
    vocab = ["ntopenkey", "ntclose", "createremotethread", "writeprocessmemory", "getsystemtime", "ldrloaddll"]
    seqs = [[vocab[i] for i in rng.integers(0, 6 if k % 2 else 3, 40)] for k in range(60)]
    y = np.array([k % 2 for k in range(60)])
    docs = [ngrams(s) for s in seqs]
    vec = TfidfVectorizer(analyzer=lambda d: d, min_df=2, sublinear_tf=True)
    X = vec.fit_transform(docs)
    lr = LogisticRegression(C=10, max_iter=2000).fit(X, y)
    names = vec.get_feature_names_out()
    m = ApiBehaviourModel(dict(zip(names, vec.idf_)), dict(zip(names, lr.coef_[0])), float(lr.intercept_[0]))
    ref = lr.predict_proba(X)[:, 1]
    mine = np.array([m.proba(s) for s in seqs])
    assert np.abs(ref - mine).max() < 1e-9


def test_roundtrip_and_short_traces(tmp_path):
    m = ApiBehaviourModel({"a": 1.0, "b": 2.0, "a>b": 1.5}, {"a": -1.0, "b": 2.0, "a>b": 0.5}, 0.1, {"trained_on": "t"})
    m.save(tmp_path)
    m2 = ApiBehaviourModel.load(tmp_path)
    assert m2.proba(["a", "b"]) == pytest.approx(m.proba(["a", "b"]), abs=1e-4)
    assert m2.score(api_sequence_to_trace(["a", "b"] * 3, "r")) is None  # too few calls
    s = m2.score(api_sequence_to_trace(["a", "b"] * MIN_CALLS, "r"))
    assert s is not None and s.scorer.startswith("api-ngram-lr") and s.contributions


@pytest.mark.skipif(not (ROOT / "models" / "api_behaviour.json").exists(), reason="model not trained")
def test_shipped_model_separates_injection_from_idle():
    m = ApiBehaviourModel.load(ROOT / "models")
    assert m.meta.get("trained_on") == "MalbehavD-V1"
    assert len(m.idf) > 100
    p = m.proba(["NtOpenProcess", "NtAllocateVirtualMemory", "WriteProcessMemory", "CreateRemoteThread"] * 10)
    assert 0.0 <= p <= 1.0
