"""Speakeasy emulation reports (Quo Vadis benign corpus) -> Trace, in the shared rule-matching line format."""
import json

import pytest

from specimen.adapters.speakeasy import speakeasy_to_trace
from specimen.detect import SigmaRule, blobs

REPORT = [
    {"ep_type": "module_entry", "apis": [
        {"pc": "0x401000", "api_name": "KERNEL32.GetModuleHandleA", "args": ["0x0"], "ret_val": "0x400000"},
        {"pc": "0x401010", "api_name": "KERNEL32.CreateProcessA",
         "args": ["0x0", "cmd.exe /c echo setup-done", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0"],
         "ret_val": "0x1"},
        {"pc": "0x401020", "api_name": "SHELL32.ShellExecuteW",
         "args": ["0x0", "open", "C:\\Program Files\\App\\help.exe", "/topic 3", "0x0", "0x1"], "ret_val": "0x2a"},
        {"pc": "0x401030", "api_name": "KERNEL32.WinExec", "args": ["0x12345", "0x1"], "ret_val": "0x21"},
    ],
     "file_access": [{"event": "create", "path": "C:\\Users\\admin\\AppData\\Local\\Temp\\setup.tmp"},
                     {"event": "read", "path": "C:\\Windows\\system32\\kernel32.dll"}],
     "registry_access": [{"event": "open_key", "path": "HKEY_LOCAL_MACHINE\\Software\\App"},
                         {"event": "write_value", "path": "HKEY_CURRENT_USER\\Software\\App", "value_name": "Installed"},
                         {"event": "create_key", "path": "HKEY_CURRENT_USER\\Software\\App\\Cache"}],
     "network_events": {"dns": [{"query": "update.example.invalid"}],
                        "traffic": [{"server": "203.0.113.5", "port": 443, "proto": "tcp"}]}},
    {"ep_type": "thread", "apis": "not-a-list", "file_access": [None, {"event": "write"}]},
]


def test_speakeasy_report_maps_to_typed_events():
    t = speakeasy_to_trace(json.dumps(REPORT).encode(), run_id="r1")
    types = [e.type for e in t.events]
    assert t.sandbox == "speakeasy" and t.source_sha256
    assert types.count("api_call") == 4
    procs = [e for e in t.events if e.type == "process_create"]
    assert [p.cmdline for p in procs] == ["cmd.exe /c echo setup-done", "C:\\Program Files\\App\\help.exe /topic 3"]
    assert any(e.type == "file_write" and e.target.endswith("setup.tmp") for e in t.events)
    assert any(e.type == "file_read" for e in t.events)
    regs = [e for e in t.events if e.type == "registry_set"]
    assert [r.target for r in regs] == ["HKEY_CURRENT_USER\\Software\\App\\Installed"]  # key creation skipped
    assert {"dns_query", "net_connect"} <= set(types)
    assert [e.ts for e in t.events] == sorted(e.ts for e in t.events)


def test_rules_match_speakeasy_lines():
    t = speakeasy_to_trace(REPORT)
    b = blobs([[e.type, e.target or "", e.cmdline or ""] for e in t.events])
    assert SigmaRule("file_event", (("TargetFilename", "C:\\Users\\*\\AppData\\Local\\Temp\\setup.tmp"),)).matches(b)
    assert SigmaRule("registry_set", (("TargetObject", "*\\Software\\App\\Installed"),)).matches(b)


@pytest.mark.parametrize("bad", [b"{}", b"[]", b"not json", b"[1, 2]"])
def test_malformed_reports_are_value_errors(bad):
    with pytest.raises(ValueError):
        speakeasy_to_trace(bad)


def test_object_with_entry_points_and_sha():
    t = speakeasy_to_trace({"sha256": "ab" * 32, "entry_points": REPORT})
    assert t.sample_sha256 == "ab" * 32
