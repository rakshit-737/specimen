from specimen.escape import defang


def test_defang_leaves_technique_ids_and_numbers_alone():
    assert defang("T1547.001 weight +0.413") == "T1547.001 weight +0.413"


def test_defang_ipv4_and_urls():
    assert defang("10.1.2.3") == "10[.]1[.]2[.]3"
    assert defang("http://mbfgq.ga/x") == "hxxp://mbfgq[.]ga/x"


def test_oversized_input_is_refused(tmp_path, monkeypatch):
    import pytest

    from specimen.hashing import read_capped
    f = tmp_path / "big.json"
    f.write_bytes(b"{}" + b" " * 3_000_000)
    monkeypatch.setenv("SPECIMEN_MAX_INPUT_MB", "1")
    with pytest.raises(ValueError, match="input cap"):
        read_capped(f)
