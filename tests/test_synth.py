from specimen.corpus import synthetic_corpus
from specimen.static_triage import load_sample, triage
from specimen.synth import pick_yara_strings, synthesize, yara_matches
from specimen.trace import load_trace


def test_yara_and_sigma(fx):
    s, data = load_sample(fx["sim_ransom.bin"][0])
    v = triage(data)
    benign = [t for t, y, _ in synthetic_corpus() if y == 0]
    d = synthesize(v, s.sha256, load_trace(fx["sim_ransom.bin"][1]), [b"hello"], benign)
    assert d.yara and "rule SPECIMEN_" in d.yara
    assert yara_matches(pick_yara_strings(v, [b"hello"]), 1, data)
    assert any("T1490".lower() in r for r in d.sigma)
    assert not d.yara_fp_hits


def test_yara_excludes_benign_strings(fx):
    _, data = load_sample(fx["sim_injector.bin"][0])
    v = triage(data)
    strs = pick_yara_strings(v, [b"xx VirtualAllocEx xx"])
    assert "VirtualAllocEx" not in strs


def test_nonspecific_sigma_dropped(fx):
    s, data = load_sample(fx["sim_ransom.bin"][0])
    from specimen.models import Event, Trace
    noisy = Trace("b", "", "x", [Event(1, "registry_set", 1, "ok.exe",
                                       target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\legit")])
    d = synthesize(triage(data), s.sha256, load_trace(fx["sim_ransom.bin"][1]), [], [noisy])
    assert not any("T1547.001".lower() in r for r in d.sigma)
    assert d.sigma_fp_hits
