import json

import pytest

from specimen.cli import main
from specimen.pipeline import run


def test_end_to_end(fx):
    rep = run(*fx["sim_injector.bin"])
    assert rep["detonated"] and rep["verdict"]["label"] == "malicious"
    assert rep["manifest"]["trace_sha256"] and len(rep["manifest"]["report_content_sha256"]) == 64
    assert "203.0.113.66:8443" in rep["iocs"]["network"]


def test_gate_skips_benign(fx):
    sp, _ = fx["benign_notes.txt"]
    rep = run(sp, fx["sim_ransom.bin"][1])  # trace supplied but gate says no
    assert not rep["detonated"] and rep["verdict"]["label"] == "benign"


def test_behavior_catches_bland(fx):
    rep = run(*fx["sim_bland.bin"])
    assert rep["static"]["label"] == "benign"
    assert rep["verdict"]["label"] == "malicious" and rep["detections"]["sigma"]


def test_report_hash_reproducible(fx):
    a, b = run(*fx["sim_ransom.bin"]), run(*fx["sim_ransom.bin"])
    assert a["manifest"]["report_content_sha256"] == b["manifest"]["report_content_sha256"]


def test_trace_sample_mismatch_rejected(fx):
    with pytest.raises(ValueError, match="evidence mismatch"):
        run(fx["sim_injector.bin"][0], fx["sim_ransom.bin"][1])


def test_cli_demo(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "reports" / "sim_ransom.md").exists()
    json.loads((tmp_path / "reports" / "sim_ransom.json").read_text())
    assert "sim-ransom" in capsys.readouterr().out
