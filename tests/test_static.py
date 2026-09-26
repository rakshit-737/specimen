from specimen.static_triage import load_sample, shannon_entropy, triage


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"aaaa") == 0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_benign_text_skipped(fx):
    _, data = load_sample(fx["benign_notes.txt"][0])
    v = triage(data)
    assert v.label == "benign" and not v.detonate


def test_injector_flagged_with_explanation(fx):
    _, data = load_sample(fx["sim_injector.bin"][0])
    v = triage(data)
    assert v.detonate and v.label in ("suspicious", "malicious")
    feats = {r.feature for r in v.reasons}
    assert "api:CreateRemoteThread" in feats
    assert any("203.0.113.66" in u for u in v.iocs["urls"])
    assert v.reasons[0].impact >= v.reasons[-1].impact


def test_bland_pe_still_detonated(fx):
    _, data = load_sample(fx["sim_bland.bin"][0])
    v = triage(data)
    assert v.label == "benign" and v.detonate and v.is_pe
