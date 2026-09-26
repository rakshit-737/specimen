"""Emitted rules must be accepted by the reference toolchains.

pySigma parses and converts every synthesized Sigma rule; yara-python
compiles every YARA rule (the ``pe`` module included). Both are optional:
the ``rules`` CI job installs them, and the tests skip where they are
absent (e.g. yara-python has no wheel for every Python/OS).
"""
from pathlib import Path

import pytest

from specimen.pipeline import run, run_report

FX = Path(__file__).parent / "fixtures" / "cape"
REPORTS = sorted(FX.glob("*.json"))


def _rules(fx):
    sigma, yara = [], []
    for p in REPORTS:
        d = run_report(p)["detections"]
        sigma += d["sigma"]
        yara += [d["yara"]] if d["yara"] else []
    for sp, tp in fx.values():
        d = run(sp, tp)["detections"]
        sigma += d["sigma"]
        yara += [d["yara"]] if d["yara"] else []
    return sigma, yara


@pytest.fixture(scope="module")
def rules(fx):
    return _rules(fx)


def test_rules_were_emitted(rules):
    sigma, yara = rules
    assert sigma and yara


def test_sigma_rules_parse_and_convert_with_pysigma(rules):
    pytest.importorskip("sigma")
    from sigma.collection import SigmaCollection

    for text in rules[0]:
        coll = SigmaCollection.from_yaml(text)
        assert not coll.errors, coll.errors
        assert len(coll.rules) == 1
        try:
            from sigma.backends.sqlite import sqliteBackend
        except ImportError:
            continue
        assert sqliteBackend().convert(coll)


def test_yara_rules_compile_with_yara_python(rules):
    yara = pytest.importorskip("yara")
    for text in rules[1]:
        yara.compile(source=text)
