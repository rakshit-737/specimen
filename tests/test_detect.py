import json
from pathlib import Path

from specimen.adapters import cape_to_trace, static_pe
from specimen.detect import (
    SigmaRule,
    blobs,
    candidates,
    image_of,
    ladder,
    literal_len,
    synthesize_sigma,
    synthesize_yara_pe,
)
from specimen.tokens import behavior_tokens, normalize, static_tokens

FX = Path(__file__).parent / "fixtures" / "cape"

DROP = ["file_write", r"C:\Users\comp\AppData\Local\iproppass\iproppass.exe", ""]
RUN = ["registry_set", r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\iproppass", ""]
EXEC = ["process_create", "x.exe", r'"C:\Users\comp\AppData\Local\Temp\DF4FD49DC53618D7F3A1.exe" --x 12']


def test_ladder_generalises_user_and_names():
    rungs = ladder(DROP[1], "path")
    assert rungs[0] == r"C:\Users\*\AppData\Local\iproppass\iproppass.exe"
    assert r"C:\Users\*\AppData\Local\iproppass\*.exe" in rungs
    assert rungs[-1] == r"C:\Users\*\AppData\Local\*\*.exe"
    assert ladder(RUN[1], "key")[-1].endswith(r"\Run\*")


def test_literal_len_ignores_generic_prefixes():
    assert literal_len(r"C:\Users\*\AppData\Local\*\*.exe") < 10
    assert literal_len(r"C:\Users\*\AppData\Local\iproppass\*.exe") >= 10


def test_environment_and_muicache_prefixes_are_not_specific():
    assert literal_len(r"HKEY_CURRENT_USER\Environment\*") == 0
    assert literal_len(r"HKEY_USERS\*\Environment\*") == 0
    assert literal_len(r"HKEY_CURRENT_USER\Software\Classes\Local Settings\MuiCache\*") < 10
    # a named value under Environment (e.g. a logon script) is still specific enough
    assert literal_len(r"HKEY_CURRENT_USER\Environment\UserInitMprLogonScript") >= 10
    env = ["registry_set", r"HKEY_CURRENT_USER\Environment\abcdef12", ""]
    res = synthesize_sigma([env], [])
    assert all(r.fields[0][1].lower() != r"hkey_current_user\environment\*" for r in res.rules)


def test_image_of():
    assert image_of(EXEC[2], "x").endswith("DF4FD49DC53618D7F3A1.exe")
    assert image_of("cmd.exe /c whoami", "") == "cmd.exe"


def test_rule_matching_is_case_insensitive_wildcard():
    r = SigmaRule("file_event", (("TargetFilename", r"C:\Users\*\AppData\Local\*\iproppass.exe"),))
    assert r.matches(blobs([["file_write", r"c:\users\bob\appdata\local\zz\IPROPPASS.EXE", ""]]))
    assert not r.matches(blobs([["file_write", r"c:\users\bob\appdata\local\zz\other.exe", ""]]))
    assert not r.matches(blobs([["registry_set", r"c:\users\bob\appdata\local\zz\iproppass.exe", ""]]))


def test_synthesis_picks_most_general_specific_rung():
    neg = [blobs([["file_write", r"C:\Users\a\AppData\Local\Microsoft\cache.exe", ""]])]
    res = synthesize_sigma([DROP], neg)
    assert len(res.rules) == 1
    pat = res.rules[0].fields[0][1]
    # "\\*\\*.exe" would hit the negative and is too generic; the stem wildcard survives
    assert pat in (r"C:\Users\*\AppData\Local\*\iproppass.exe", r"C:\Users\*\AppData\Local\iproppass\*.exe")
    sib = blobs([["file_write", r"C:\Users\x\AppData\Local\qwerty\iproppass.exe", ""]])
    assert res.rules[0].matches(sib) or pat.endswith(r"iproppass\*.exe")


def test_synthesis_rejects_rules_that_hit_negatives():
    neg = [blobs([DROP, RUN, EXEC])]
    res = synthesize_sigma([DROP, RUN], neg)
    assert res.rules == [] and res.rejected_nonspecific == 2


def test_sigma_text_is_valid_yaml_shape():
    res = synthesize_sigma([RUN, DROP, EXEC], [])
    text = res.rules[0].to_sigma("a" * 64, technique="T1547.001")
    assert "logsource:" in text and "condition: selection" in text and "attack.t1547.001" in text
    assert len(candidates([RUN, DROP, EXEC, DROP])) == 3


def test_yara_pe_rule_from_real_fixture():
    doc = json.loads((FX / "avast_emotet_1.json").read_text())
    toks = static_tokens(static_pe(doc))
    rule = synthesize_yara_pe(toks, [])
    assert rule and rule.imphash and len(rule.imports) >= 3
    assert rule.matches(set(toks))
    text = rule.to_yara("SPECIMEN_x", "b" * 64, {"enumservicesstatusw": "EnumServicesStatusW"})
    assert 'import "pe"' in text and "pe.imphash()" in text and "EnumServicesStatusW" in text
    # an identical negative disables both the imphash and the import clause
    assert synthesize_yara_pe(toks, [set(toks)]) is None


def test_tokens_normalise_run_specific_noise():
    assert normalize(r"C:\Users\comp\AppData\Roaming\{12345678-1234-1234-1234-123456789ABC}\a1b2c3d4.exe") \
        == r"%appdata%\<guid>\<hex>.exe"
    doc = json.loads((FX / "avast_emotet_2.json").read_text())
    toks = behavior_tokens(cape_to_trace(doc))
    assert any(t.startswith("mutex_create:") for t in toks)
    assert all(len(t) < 400 for t in toks)
