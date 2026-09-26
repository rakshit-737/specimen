import json
from pathlib import Path

import pytest

from specimen.adapters import (
    CapeFormatError,
    api_sequence_to_trace,
    cape_to_trace,
    load_cape,
    looks_like_cape,
    static_pe,
)
from specimen.adapters.cape import command_image
from specimen.provenance import reconstruct

FX = Path(__file__).parent / "fixtures" / "cape"


def test_full_report_uses_call_log_and_network():
    t = load_cape(FX / "full_cape_synthetic.json")
    assert t.sandbox == "cape" and len(t.source_sha256) == 64
    types = {e.type for e in t.events}
    assert {"process_inject", "registry_set", "mutex_create", "file_delete", "process_create",
            "dns_query", "net_connect"} <= types
    # duplicated tcp flow collapsed
    assert sum(e.type == "net_connect" for e in t.events) == 1
    # timestamps are relative to the first call and sorted
    assert t.events[0].ts == 0.0 and [e.ts for e in t.events] == sorted(e.ts for e in t.events)
    inj = next(e for e in t.events if e.type == "process_inject")
    assert inj.extra["target_pid"] == 3300


def test_full_report_graph_and_techniques():
    g, tl = reconstruct(load_cape(FX / "full_cape_synthetic.json"))
    techs = {x.technique for x in tl}
    assert {"T1055", "T1547.001", "T1490", "T1622", "T1071.004"} <= techs
    assert any(e.relation == "spawned" for e in g.edges)
    # api calls without a technique are not graph nodes
    assert not any(n.label == "NtOpenFile" for n in g.nodes.values())


@pytest.mark.parametrize("name", ["avast_emotet_1", "avast_lokibot_1", "avast_njrat_1"])
def test_reduced_avast_reports(name):
    doc = json.loads((FX / f"{name}.json").read_text())
    assert looks_like_cape(doc)
    t = cape_to_trace(doc, run_id=name)
    assert t.sandbox == "cape-summary"
    assert all(e.extra.get("synthetic_ts") for e in t.events)
    assert any(e.type == "mutex_create" for e in t.events)
    assert static_pe(doc)["imphash"]


def test_rejects_garbage():
    with pytest.raises(CapeFormatError):
        cape_to_trace({"behavior": {}})
    with pytest.raises(CapeFormatError):
        cape_to_trace(["not", "a", "report"])  # type: ignore[arg-type]


def test_hostile_values_are_coerced():
    doc = {"behavior": {"processes": [{"process_id": "x", "parent_id": None, "environ": [],
                                       "calls": [{"api": "RegSetValueExA", "arguments": "junk"},
                                                 "not-a-dict"]}],
                        "summary": {"mutexes": ["A" * 10_000]}}}
    t = cape_to_trace(doc)
    assert all(len(e.target or "") <= 512 for e in t.events)


def test_command_image():
    assert command_image('"C:\\Users\\comp\\AppData\\Local\\Temp\\AB12.exe" /x') == "AB12.exe"
    assert command_image("cmd.exe /c whoami") == "cmd.exe"


def test_api_sequence_adapter():
    t = api_sequence_to_trace(["LdrLoadDll", "", "NtCreateFile"], "s1")
    assert [e.target for e in t.events] == ["LdrLoadDll", "NtCreateFile"]
    assert t.sandbox == "api-sequence"
