"""CLI success and error paths, and model resolution independent of the working directory."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from specimen import __version__, pipeline
from specimen.adapters.api_seq import api_sequence_to_trace
from specimen.cli import main
from specimen.static_triage import MAX_BYTES, load_sample

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures"


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


@pytest.mark.parametrize("argv", [
    ["triage", "nope.bin"],
    ["analyze", "nope.bin"],
    ["report", "nope.json"],
    ["triage-ember", "nope.jsonl"],
    ["batch", "no/such/dir"],
])
def test_missing_inputs_exit_2_with_one_line(argv, capsys):
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "not found" in err and "Traceback" not in err


def test_batch_empty_dir_is_an_error(tmp_path):
    with pytest.raises(SystemExit) as e:
        main(["batch", str(tmp_path)])
    assert e.value.code == 2


def test_report_and_batch_success(tmp_path, capsys):
    assert main(["report", str(FX / "cape" / "avast_njrat_1.json"), "--out", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"]["label"] and "behaviour_scorer" in out
    assert (tmp_path / "avast_njrat_1.md").exists()
    assert main(["batch", str(FX / "cape"), "--out", str(tmp_path / "b"), "--workers", "1"]) == 0
    assert main(["batch", str(FX / "cape"), "--out", str(tmp_path / "b"), "--workers", "1"]) == 0
    assert "already done" in capsys.readouterr().out


def test_analyze_with_bundled_dummy_sample(tmp_path, capsys):
    rc = main(["analyze", str(FX / "sysmon" / "lab_sample.bin"), "--trace", str(FX / "sysmon" / "lab_run.xml"),
               "--force-detonate", "--out", str(tmp_path)])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["detonated"] is True


def test_evidence_mismatch_is_a_short_error(tmp_path, capsys):
    trace = tmp_path / "t.json"
    trace.write_text(json.dumps({"run_id": "r", "sample_sha256": "0" * 64, "sandbox": "x", "events": []}))
    s = tmp_path / "s.bin"
    s.write_bytes(b"MZ" + b"\0" * 64)
    assert main(["analyze", str(s), "--trace", str(trace)]) == 1
    assert "evidence mismatch" in capsys.readouterr().err


def test_triage_ember_without_model_names_files(tmp_path, monkeypatch, capsys):
    f = tmp_path / "x.jsonl"
    f.write_text("{}\n")
    monkeypatch.setenv("SPECIMEN_MODELS", str(tmp_path / "empty"))
    assert main(["triage-ember", str(f)]) == 1
    assert "static_lgbm.txt" in capsys.readouterr().err


def test_api_model_is_packaged_and_cwd_independent(tmp_path):
    code = ("from specimen.pipeline import api_model, behaviour_score;"
            "from specimen.adapters.api_seq import api_sequence_to_trace;"
            "m = api_model(); assert m is not None;"
            "t = api_sequence_to_trace(['NtOpenFile','NtReadFile','NtClose']*10, 'r');"
            "print(behaviour_score(t).scorer)")
    env = {k: v for k, v in os.environ.items() if k != "SPECIMEN_MODELS"}
    env["PYTHONPATH"] = str(ROOT)
    out = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "api-ngram-lr" in out.stdout


def test_planted_cwd_model_is_ignored(tmp_path, monkeypatch):
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "api_behaviour.json").write_text('{"meta":{"trained_on":"PLANTED"},"intercept":0,"tokens":{}}')
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SPECIMEN_MODELS", raising=False)
    pipeline.api_model.cache_clear()
    try:
        assert "PLANTED" not in pipeline.api_model().meta.get("trained_on", "")
    finally:
        pipeline.api_model.cache_clear()


def test_end_to_end_report_uses_real_api_scorer():
    t = api_sequence_to_trace(["NtCreateFile", "NtWriteFile", "RegSetValueExW", "NtClose"] * 8, "r")
    assert pipeline.behaviour_score(t).scorer == "api-ngram-lr (MalbehavD-V1)"


def test_large_sample_hashes_whole_file(tmp_path):
    p = tmp_path / "big.bin"
    with open(p, "wb") as f:
        f.seek(MAX_BYTES + 20)
        f.write(b"x")
    import hashlib
    s, data = load_sample(p)
    assert s.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()
    assert s.size == MAX_BYTES + 21 and s.analysed_bytes == MAX_BYTES and len(data) == MAX_BYTES
