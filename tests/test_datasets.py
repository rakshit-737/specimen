import bz2
import io
import json
import tarfile
import zipfile

from specimen.datasets import iter_avast, iter_ember, iter_malbehavd, iter_zip, parse_avast_labels

LABELS = "sha256,classification_family,classification_type,date\naa,Emotet,banker,2019-01-02\nbb,Zeus,banker,2019-09-01\n"


def _avast_zip(path, nested=True):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("public_small_reports/aa.json", json.dumps({"behavior": {"summary": {"mutexes": ["m1"]}}}))
        z.writestr("public_small_reports/bb.json", json.dumps({"behavior": {"summary": {"mutexes": ["m2"]}}}))
        z.writestr("public_small_reports/zz.json", json.dumps({"behavior": {}}))  # unlabelled -> skipped
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("public_labels.csv", LABELS)
        if nested:
            z.writestr("reports.zip", inner.getvalue())
        else:
            for info in zipfile.ZipFile(inner).infolist():
                z.writestr(info.filename, zipfile.ZipFile(inner).read(info))


def test_labels_and_split():
    lab = parse_avast_labels(LABELS)
    assert lab["aa"].split == "train" and lab["bb"].split == "test"


def test_iter_avast_nested_and_flat(tmp_path):
    for nested in (True, False):
        p = tmp_path / f"a{nested}.zip"
        _avast_zip(p, nested)
        got = [(lab.family, rep["behavior"]["summary"]["mutexes"][0]) for lab, rep in iter_avast(p)]
        assert got == [("Emotet", "m1"), ("Zeus", "m2")]


def test_iter_zip_truncated_is_tolerated(tmp_path):
    p = tmp_path / "full.zip"
    _avast_zip(p, nested=False)
    raw = p.read_bytes()
    cut = tmp_path / "cut.zip"
    cut.write_bytes(raw[: len(raw) // 2] + b"\x00" * 1000)  # partial download, zero-filled tail
    names = []
    for name, _chunks in iter_zip(cut):
        names.append(name)
    assert names and names[0] == "public_labels.csv"
    list(iter_avast(cut))  # must not raise


def test_iter_ember_prefix(tmp_path):
    rows = [{"sha256": str(i), "label": [0, 1, -1][i % 3], "appeared": "2018-01"} for i in range(30)]
    payload = "".join(json.dumps(r) + "\n" for r in rows).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("ember2018/train_features_0.jsonl")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    comp = bz2.compress(buf.getvalue())
    full = tmp_path / "e.tar.bz2"
    full.write_bytes(comp)
    got = list(iter_ember(full))
    assert len(got) == 20 and {r["label"] for r in got} == {0, 1}
    part = tmp_path / "p.tar.bz2"
    part.write_bytes(comp[: len(comp) // 2])
    assert len(list(iter_ember(part))) <= 20  # truncated: no exception


def test_iter_malbehavd(tmp_path):
    p = tmp_path / "m.csv"
    p.write_text("sha256,labels,0,1,2\nabc,1,LdrLoadDll,NtClose,\ndef,0,GetTickCount,,\n")
    assert list(iter_malbehavd(p)) == [("abc", 1, ["LdrLoadDll", "NtClose"]), ("def", 0, ["GetTickCount"])]
