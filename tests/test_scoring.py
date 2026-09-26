from specimen.corpus import synthetic_corpus
from specimen.scoring import featurize, score, trained
from specimen.trace import load_trace


def test_model_accuracy_on_heldout():
    model, _, _ = trained()
    held = synthetic_corpus(n=60, seed=99)
    correct = sum((model.predict(featurize(t)) >= 0.5) == bool(y) for t, y, _ in held)
    assert correct / len(held) >= 0.9


def test_family_match(fx):
    assert score(load_trace(fx["sim_ransom.bin"][1])).family == "sim-ransom"
    assert score(load_trace(fx["sim_injector.bin"][1])).family == "sim-injector"


def test_benign_trace_scores_low():
    t = next(t for t, y, _ in synthetic_corpus() if y == 0)
    s = score(t)
    assert s.label == "benign" and s.family is None
