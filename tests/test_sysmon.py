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


SAMPLE = FX.parent / "lab_sample.bin"


def test_pipeline_accepts_bound_sysmon_trace():
    assert is_sysmon(FX.read_bytes()) and not is_sysmon(b'{"run_id": "x", "events": []}')
    rep = run(SAMPLE, FX, force_detonate=True)
    assert rep["detonated"] and rep["graph"]["nodes"] > 3
    assert "T1547.001" in rep["techniques"]
    assert rep["manifest"]["trace_binding"].startswith("bound")
    assert rep["manifest"]["sample_sha256"] == "b81a2a0872b6f42e1237dd33a08f48f687d7e1a4747be20c8805117148039bba"


def test_sysmon_hashes_bind_the_trace_to_its_sample(tmp_path):
    other = tmp_path / "other.bin"
    other.write_bytes(b"an unrelated 34-byte text file....")
    with pytest.raises(ValueError, match="evidence mismatch"):
        run(other, FX, force_detonate=True)
    t = sysmon_to_trace(FX.read_bytes())
    assert t.sample_sha256 == ""  # no claimed sample -> unbound, hashes still recorded on the events
    assert any(e.extra.get("sha256") for e in t.events)


def test_sysmon_export_without_hashes_is_unbound_and_low_confidence(tmp_path):
    raw = FX.read_bytes().replace(b'<Data Name="Hashes">', b'<Data Name="NotHashes">')
    p = tmp_path / "nohash.xml"
    p.write_bytes(raw)
    other = tmp_path / "other.bin"
    other.write_bytes(b"MZ" + b"\x00" * 64)
    rep = run(other, p, force_detonate=True)
    assert rep["manifest"]["trace_binding"].startswith("unbound")
    assert rep["verdict"]["confidence"].startswith("low (trace not bound")


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-8-sig"])
def test_utf16_and_utf32_exports(tmp_path, encoding):
    """Windows PowerShell 5.1 '>' writes UTF-16LE with a BOM; plain utf-16-le/-be have none."""
    p = tmp_path / f"lab_{encoding}.xml"
    p.write_bytes(FX.read_bytes().decode("utf-8").encode(encoding))
    assert is_sysmon(p.read_bytes())
    rep = run(SAMPLE, p, force_detonate=True)
    assert rep["detonated"] and "T1547.001" in rep["techniques"]


def test_malformed_xml_is_a_value_error():
    with pytest.raises(ValueError, match="malformed Sysmon XML"):
        sysmon_to_trace(b"<Event><EventData><Data Name='x'>unclosed</EventData>")
