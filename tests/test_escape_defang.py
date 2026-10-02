from specimen.escape import defang


def test_defang_leaves_technique_ids_and_numbers_alone():
    assert defang("T1547.001 weight +0.413") == "T1547.001 weight +0.413"


def test_defang_ipv4_and_urls():
    assert defang("10.1.2.3") == "10[.]1[.]2[.]3"
    assert defang("http://mbfgq.ga/x") == "hxxp://mbfgq[.]ga/x"
