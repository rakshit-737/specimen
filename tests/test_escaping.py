"""Untrusted report strings must not change the structure of emitted rules or Markdown,
and emitted Sigma must keep its meaning under real Sigma semantics."""
import json
import re
import sqlite3
from pathlib import Path

import pytest

from specimen.detect import SigmaRule, YaraPeRule, literal_len
from specimen.escape import defang, md_text, sigma_value, yara_str
from specimen.pipeline import run_report
from specimen.report import render_markdown

REPORTS = sorted((Path(__file__).parent / "fixtures" / "cape").glob("*.json"))

BS = "\\"
CRAFTED = {
    "target": {"file": {"sha256": "not-a-hash\"; evil", "name": "x.exe"}},
    "behavior": {"summary": {
        "executed_commands": ["cmd.exe /c echo abcdefghijkl'\n        Image|endswith: '.injected",
                              "notepad.exe readme\n--8<-- \"LICENSE\"\n"],
        "write_keys": [BS.join(["HKEY_CURRENT_USER", "Software", "Microsoft", "Windows", "CurrentVersion", "Run",
                                "O'Reilly Updater"])],
        "write_files": [BS.join(["C:", "Users", "comp", "AppData", "Roaming", "evil*name?.exe"])],
        "mutexes": ['<b id="specimen-audit">INJECTED</b>'],
    }},
    "static": {"pe": {"imphash": "zz\" or true", "imports": [
        {"dll": "kernel32.dll", "imports": [{"name": 'Sleep"Ex'}, {"name": "A\\B"}, {"name": "CCCC"}]}]}},
}


@pytest.fixture(scope="module")
def crafted(tmp_path_factory):
    p = tmp_path_factory.mktemp("c") / "crafted.json"
    p.write_text(json.dumps(CRAFTED))
    return run_report(p)


def test_sigma_value_escaping():
    assert sigma_value(BS.join(["C:", "Users", "*", "a?b.exe"])) == "C:\\\\Users\\\\*\\\\a\\?b.exe"
    assert yara_str('a"b\\c\n') == 'a\\"b\\\\c\\x0a'


def test_hive_roots_are_not_specific():
    assert literal_len("HKEY_CURRENT_USER" + BS + "*") == 0
    assert literal_len(BS.join(["C:", "Windows", "Microsoft.NET", "Framework", "*", "*.exe"])) < 10


def test_crafted_report_cannot_inject_rule_fields(crafted):
    yaml = pytest.importorskip("yaml")
    for text in crafted["detections"]["sigma"]:
        doc = yaml.safe_load(text)
        for key in doc["detection"]["selection"]:
            assert key in ("Image", "CommandLine", "TargetObject", "TargetFilename"), key
    y = crafted["detections"]["yara"] or ""
    assert "or true" not in y and "evil" not in y


def test_crafted_report_markdown_is_inert(crafted):
    md = render_markdown(crafted)
    assert '<b id="specimen-audit">' not in md
    assert "--8<--" not in md.replace("```", "")


def test_defang():
    assert defang("http://mbfgq.ga/Dboy/five/fre.php") == "hxxp://mbfgq[.]ga/Dboy/five/fre.php"
    assert defang("C:\\x\\kernel32.dll") == "C:\\x\\kernel32.dll"
    assert "<" not in md_text("<script>")


def test_yara_rule_rejects_bad_hex():
    r = YaraPeRule("ZZ", (("kernel32.dll", 'a"b'), ("k", "c"), ("k", "d")), 2)
    out = r.to_yara("9bad-name", "nothex")
    assert 'pe.imphash()' not in out and "rule r_9bad_name" in out and 'sample_sha256 = "unknown"' in out


def test_emitted_sigma_has_no_escaped_wildcards_and_fires_in_sqlite():
    """Convert every emitted rule with pySigma's SQLite backend and run it on the
    source report's own events: Sigma semantics must agree with the internal matcher."""
    pytest.importorskip("sigma")
    sqlite_backend = pytest.importorskip("sigma.backends.sqlite")
    from sigma.collection import SigmaCollection
    from sigma.validators.core.values import EscapedWildcardValidator

    from specimen.adapters.cape import cape_to_trace
    from specimen.detect import event_line

    for rp in REPORTS:
        rep = run_report(rp)
        trace = cape_to_trace(json.loads(rp.read_bytes()))
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE logs (Image TEXT, CommandLine TEXT, TargetObject TEXT, TargetFilename TEXT)")
        for e in trace.events:
            r = event_line(e.type, e.target or "", e.cmdline or "")
            if not r or not r[1]:
                continue
            if r[0] == "process_creation":
                img, cmd = r[1].split("\t", 1)
                db.execute("INSERT INTO logs (Image, CommandLine) VALUES (?, ?)", (img, cmd))
            elif r[0] == "registry_set":
                db.execute("INSERT INTO logs (TargetObject) VALUES (?)", (r[1],))
            else:
                db.execute("INSERT INTO logs (TargetFilename) VALUES (?)", (r[1],))
        for text in rep["detections"]["sigma"]:
            coll = SigmaCollection.from_yaml(text)
            rule = coll.rules[0]
            assert not list(EscapedWildcardValidator().validate(rule)), text
            q = sqlite_backend.sqliteBackend().convert(coll)[0]
            q = re.sub(r"FROM\s+\S+", "FROM logs", q, count=1)
            assert db.execute(q).fetchall(), f"{rp.name}: rule does not fire on its own run\n{text}\n{q}"


def test_internal_matcher_agrees_with_pattern():
    r = SigmaRule("file_event", (("TargetFilename", BS.join(["C:", "Users", "*", "x.bat"])),))
    assert r.matches({"file_event": BS.join(["C:", "Users", "bob", "x.bat"])})


def test_shipped_report_path_uses_packaged_negatives_and_no_hive_root_rules():
    from specimen.negatives import meta
    assert meta().get("families"), "packaged negative corpus missing"
    rep = run_report(REPORTS[[p.name for p in REPORTS].index("avast_njrat_1.json")])
    assert rep["manifest"]["negative_corpus"]["packaged"] is True
    for text in rep["detections"]["sigma"]:
        val = text.split("selection:")[1].splitlines()[1].split(": ", 1)[1].strip("'")
        assert val not in ("HKEY_CURRENT_USER\\*", "HKEY_LOCAL_MACHINE\\*"), text
        assert "Framework\\*\\*.exe" not in val
