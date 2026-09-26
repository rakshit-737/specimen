import json
from pathlib import Path

import pytest

from specimen.adapters.sysmon import sysmon_to_trace
from specimen.pipeline import is_sysmon, run

FX = Path(__file__).parent / "fixtures" / "sysmon" / "lab_run.xml"


def test_xml_export_maps_to_typed_events():
    t = sysmon_to_trace(FX.read_bytes(), "lab")
    types = [e.type for e in t.events]
    assert t.sandbox == "sysmon"
    assert types.count("process_create") == 2
    for ty in ("dns_query", "net_connect", "file_write", "registry_set", "process_inject", "file_delete"):
        assert ty in types
    assert "registry_read" not in types and len(t.events) == 8  # CreateKey + ProcessTerminate dropped
    assert t.events[0].ts == 0.0 and t.events[-1].ts == pytest.approx(4.9, abs=1e-3)
    net = next(e for e in t.events if e.type == "net_connect")
    assert net.target == "203.0.113.10:443"


def test_json_lines_export_nested_and_flat():
    lines = [json.dumps({"EventID": 22, "EventData": {"UtcTime": "2026-09-01 10:00:00.000", "ProcessId": "7",
                                                      "Image": "a.exe", "QueryName": "x.invalid"}}),
             json.dumps({"EventID": 11, "ProcessId": "7", "Image": "a.exe", "TargetFilename": "C:\t\b.dll"})]
    raw = "\n".join(lines).encode()
    assert is_sysmon(raw)
    t = sysmon_to_trace(raw)
    assert [e.type for e in t.events] == ["dns_query", "file_write"]
    assert t.events[1].extra.get("synthetic_ts")


def test_rejects_dtd():
    with pytest.raises(ValueError):
        sysmon_to_trace(b'<!DOCTYPE x [<!ENTITY a "b">]><Event/>')


def test_pipeline_accepts_sysmon_trace(tmp_path):
    s = tmp_path / "sample.bin"
    s.write_bytes(b"MZ" + b"\x00" * 64 + b"powershell -enc http://203.0.113.10/a VirtualAllocEx")
    assert is_sysmon(FX.read_bytes()) and not is_sysmon(b'{"run_id": "x", "events": []}')
    rep = run(s, FX, force_detonate=True)
    assert rep["detonated"] and rep["graph"]["nodes"] > 3
    assert "T1547.001" in rep["techniques"]
