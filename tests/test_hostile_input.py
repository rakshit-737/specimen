"""Hostile or malformed reports and traces: coerced or refused with a one-line error, never a traceback."""
import json
from pathlib import Path

import pytest

from specimen.cli import main
from specimen.coerce import finite_float, loads, safe_int
from specimen.pipeline import run, run_report
from specimen.tokens import static_tokens
from specimen.trace import TraceError, parse_trace

FX = Path(__file__).parent / "fixtures"
NJRAT = json.loads((FX / "cape" / "avast_njrat_1.json").read_text())


def _with_pe(**pe_patch) -> dict:
    doc = json.loads(json.dumps(NJRAT))
    doc.setdefault("static", {}).setdefault("pe", {}).update(pe_patch)
    return doc


@pytest.mark.parametrize("entropy", [float("inf"), float("-inf"), float("nan"), "inf", "lots", None, 1e308])
def test_non_finite_section_entropy_is_coerced(tmp_path, entropy):
    doc = _with_pe(sections=[{"name": ".text", "entropy": entropy}], imported_dll_count="lots")
    p = tmp_path / "r.json"
    p.write_text(json.dumps(doc))  # json writes Infinity / NaN tokens, which json.loads accepts
    rep = run_report(p)
    json.dumps(rep, allow_nan=False, default=str)  # the report itself is strict JSON
    assert rep["verdict"]["label"] in ("benign", "suspicious", "malicious")


def test_static_tokens_never_raise():
    toks = static_tokens({"sections": [{"name": "a", "entropy": float("nan")}, "junk"],
                          "imported_dll_count": 1e999, "imphash": "x"})
    assert "sec_ent:a:0" in toks and "ndll:0" in toks


@pytest.mark.parametrize("event, msg", [
    ({"ts": 1e999, "type": "file_write", "pid": 1, "image": "a"}, "finite"),
    ({"ts": float("nan"), "type": "file_write", "pid": 1, "image": "a"}, "finite"),
    ({"ts": 0, "type": "file_write", "pid": 1e999, "image": "a"}, "finite"),
    ({"ts": 0, "type": "file_write", "pid": "x", "image": "a"}, "event 0"),
])
def test_native_trace_rejects_non_finite_numbers(event, msg):
    with pytest.raises(TraceError, match=msg):
        parse_trace(json.dumps({"events": [event]}).encode())


def test_deeply_nested_json_is_a_value_error():
    with pytest.raises(ValueError, match="nested too deeply"):
        loads(b"[" * 200_000 + b"]" * 200_000)


@pytest.mark.parametrize("payload, cmd", [
    (b"[" * 200_000, "report"),
    (b'{"behavior": {"summary": {}}, "static": {"pe": {"sections": [{"entropy": 1e999}]}}}', "report"),
    (b"<Event><EventData><Data Name='Image'>x</Data></EventData>", "analyze"),
    (b'{"events": [{"ts": 1, "type": "file_write", "pid": 1e999, "image": "a"}]}', "analyze"),
], ids=["deep-nesting", "infinite-entropy", "malformed-sysmon-xml", "infinite-pid"])
def test_cli_reports_malformed_input_without_traceback(tmp_path, capsys, payload, cmd):
    p = tmp_path / ("in.xml" if payload.startswith(b"<") else "in.json")
    p.write_bytes(payload)
    s = tmp_path / "s.bin"
    s.write_bytes(b"MZ" + b"\0" * 64)
    argv = ["report", str(p)] if cmd == "report" else ["analyze", str(s), "--trace", str(p), "--force-detonate"]
    rc = main(argv)
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert rc in (0, 1)
    if rc == 1:
        assert err.startswith("specimen: error:") and len(err.strip().splitlines()) == 1


def test_written_reports_are_strict_json(tmp_path):
    """NaN timestamps are refused at parse time, and report files never contain NaN/Infinity tokens."""
    with pytest.raises(TraceError):
        parse_trace(b'{"events": [{"ts": NaN, "type": "file_write", "pid": 1, "image": "a"}]}')
    assert main(["report", str(FX / "cape" / "avast_njrat_1.json"), "--out", str(tmp_path)]) == 0
    text = (tmp_path / "avast_njrat_1.json").read_text()
    assert "NaN" not in text and "Infinity" not in text
    json.loads(text, parse_constant=lambda c: pytest.fail(f"non-strict JSON constant {c}"))


def test_coerce_helpers():
    assert finite_float("nan", 1.0) == 1.0 and finite_float(9.5, 0, 0, 8) == 8
    assert safe_int(1e999, -1) == -1 and safe_int("0x10") == 16 and safe_int(True, 3) == 3


def test_analyze_and_report_emit_identical_sigma_for_the_same_cape_input(tmp_path):
    """Both commands use the same v2 synthesizer and negative corpus (only the hash in the
    description differs, because report-only analysis names rules after the report)."""
    cape = FX / "cape" / "avast_njrat_1.json"
    s = tmp_path / "s.bin"
    s.write_bytes(b"inert bytes")
    a = run(s, cape, force_detonate=True)
    r = run_report(cape)

    def selections(rep):
        return [t.split("detection:", 1)[1] for t in rep["detections"]["sigma"]]
    assert selections(a) and selections(a) == selections(r)
    assert a["manifest"]["negative_corpus"] == r["manifest"]["negative_corpus"]
