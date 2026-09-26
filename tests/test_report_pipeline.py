import json
from pathlib import Path

import pytest

from specimen.cli import main
from specimen.jobqueue import ledger_state, run_batch
from specimen.pipeline import run, run_report
from specimen.report import render_markdown
from specimen.static_triage import triage_pe_metadata

FX = Path(__file__).parent / "fixtures" / "cape"


@pytest.fixture(autouse=True)
def _no_models(monkeypatch, tmp_path):
    # tests must not depend on locally trained models
    monkeypatch.setenv("SPECIMEN_MODELS", str(tmp_path / "no-models"))
    from specimen import pipeline
    pipeline.family_model.cache_clear()
    yield
    pipeline.family_model.cache_clear()


def test_report_only_pipeline_on_real_avast_report():
    rep = run_report(FX / "avast_lokibot_1.json")
    assert rep["detonated"] and rep["verdict"]["label"] in ("suspicious", "malicious")
    assert rep["manifest"]["execution"].startswith("report-only")
    assert len(rep["manifest"]["report_sha256"]) == 64
    assert rep["detections"]["yara"] and 'import "pe"' in rep["detections"]["yara"]
    assert rep["behavior"]["family"] is None  # no trained model -> no fake attribution
    md = render_markdown(rep)
    assert "## Timeline" in md and "## Evidence manifest" in md


def test_full_cape_report_pipeline_graph():
    rep = run_report(FX / "full_cape_synthetic.json")
    assert {"T1055", "T1547.001"} <= set(rep["techniques"])
    assert rep["graph"]["edges"] > 0
    assert all(0 <= t["anomaly"] <= 1 for t in rep["timeline"])


def test_analyze_accepts_cape_trace_and_checks_evidence_binding(fx, tmp_path):
    import hashlib
    sample = fx["sim_injector.bin"][0]
    with pytest.raises(ValueError, match="evidence mismatch"):
        run(sample, FX / "full_cape_synthetic.json")
    doc = json.loads((FX / "full_cape_synthetic.json").read_text())
    doc["target"]["file"]["sha256"] = hashlib.sha256(sample.read_bytes()).hexdigest()
    bound = tmp_path / "bound.json"
    bound.write_text(json.dumps(doc))
    rep = run(sample, bound)
    assert rep["detonated"] and rep["behavior"]["probability"] > 0.5


def test_pe_metadata_gate_is_explainable():
    pe = json.loads((FX / "avast_emotet_1.json").read_text())["static"]["pe"]
    v = triage_pe_metadata(pe)
    assert v.detonate and v.is_pe and 0 < v.score < 1
    assert any(r.feature == "high_section_entropy" for r in v.reasons)


def test_batch_queue_is_resumable(tmp_path):
    out = tmp_path / "batch"
    first = run_batch(FX.glob("avast_*.json"), out, workers=1)
    assert first and all(r["status"] == "done" for r in first)
    assert run_batch(FX.glob("avast_*.json"), out, workers=1) == []  # all done -> nothing re-run
    bad = tmp_path / "in"
    bad.mkdir()
    (bad / "broken.json").write_text("{not json")
    res = run_batch(bad.glob("*.json"), out, workers=1)
    assert res[0]["status"] == "failed" and "JSONDecodeError" in res[0]["error"]
    assert len(ledger_state(out / "jobs.jsonl")) == 5


def test_cli_report(tmp_path, capsys):
    assert main(["report", str(FX / "avast_njrat_1.json"), "--out", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["yara"] is True and (tmp_path / "avast_njrat_1.md").exists()
