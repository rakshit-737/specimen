import json
import os
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from specimen.ml.avast import report_record  # noqa: E402
from specimen.ml.ember import feature_names, heuristic_score, vectorize  # noqa: E402
from specimen.ml.family import FamilyModel  # noqa: E402

pytestmark = pytest.mark.ml
FX = Path(__file__).parent / "fixtures" / "cape"


def ember_row(mal: bool) -> dict:
    return {
        "sha256": "0" * 64, "label": int(mal), "appeared": "2018-01",
        "histogram": [10] * 256, "byteentropy": [1] * 256,
        "strings": {"numstrings": 10, "avlength": 6.0, "printabledist": [1] * 96, "printables": 96,
                    "entropy": 5.0, "paths": 1, "urls": 2 if mal else 0, "registry": 0, "MZ": 1},
        "general": {"size": 1000, "vsize": 4096, "has_debug": 0, "exports": 0, "imports": 3,
                    "has_relocations": 1, "has_resources": 0, "has_signature": 0, "has_tls": 0, "symbols": 0},
        "header": {"coff": {"timestamp": 1, "machine": "I386", "characteristics": ["EXECUTABLE_IMAGE"]},
                   "optional": {"subsystem": "WINDOWS_GUI", "dll_characteristics": [], "magic": "PE32"}},
        "section": {"entry": ".text", "sections": [
            {"name": "UPX1" if mal else ".text", "size": 512, "entropy": 7.9 if mal else 5.0, "vsize": 600,
             "props": ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]}]},
        "imports": {"KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] if mal
                    else ["GetTickCount"]},
        "exports": [], "datadirectories": [{"name": "IMPORT_TABLE", "size": 10, "virtual_address": 20}],
    }


def test_ember_vector_shape_and_names():
    v = vectorize(ember_row(True))
    assert v.shape == (len(feature_names()),) and np.isfinite(v).all()


def test_heuristic_baseline_orders_obvious_cases():
    assert heuristic_score(ember_row(True)) > heuristic_score(ember_row(False))


def test_static_model_train_explain_roundtrip(tmp_path):
    pytest.importorskip("lightgbm")
    from specimen.ml.ember import StaticModel, train
    rng = np.random.default_rng(0)
    X = np.vstack([vectorize(ember_row(i % 2 == 1)) + rng.normal(0, 0.01, len(feature_names()))
                   for i in range(80)]).astype(np.float32)
    y = np.asarray([i % 2 for i in range(80)])
    m = StaticModel(train(X, y, rounds=20), 0.5, {"test": True})
    assert m.predict(X[1:2])[0] > m.predict(X[0:1])[0]
    assert m.explain(X[1]) and all(isinstance(n, str) for n, _ in m.explain(X[1]))
    m.save(tmp_path)
    m2 = StaticModel.load(tmp_path)
    assert abs(m2.predict(X[1:2])[0] - m.predict(X[1:2])[0]) < 1e-9


def test_family_model_fit_explain_roundtrip(tmp_path):
    docs = [["mutex:a", "file_write:x"], ["mutex:a", "file_write:y"], ["mutex:b", "reg:z"], ["mutex:b", "reg:w"]] * 5
    labels = ["A", "A", "B", "B"] * 5
    m = FamilyModel.fit(docs, labels)
    assert m.predict([["mutex:a"], ["mutex:b"]]) == ["A", "B"]
    assert m.explain(["mutex:a", "noise"], "A")[0][0] == "mutex:a"
    m.save(tmp_path, {"n": 20})
    assert FamilyModel.load(tmp_path).predict([["mutex:b"]]) == ["B"]


def test_avast_record_from_real_report():
    rec = report_record(json.loads((FX / "avast_lokibot_1.json").read_text()), "x")
    assert rec["beh"] and rec["static"] and rec["imphash"]
    assert all(e[0] in ("process_create", "registry_set", "file_write", "service_create") for e in rec["events"])


@pytest.mark.realdata
def test_real_avast_cache_if_present():
    root = Path(os.environ.get("SPECIMEN_DATA", "data"))
    cache = root / "cache" / "avast_tokens.jsonl.gz"
    if not cache.exists():
        pytest.skip("Avast-CTU cache not built (run scripts/download_data.py + benchmarks)")
    from specimen.ml.avast import load_cache
    recs = [r for _, r in zip(range(200), load_cache(cache))]
    assert len({r["family"] for r in recs}) >= 1 and all(r["split"] in ("train", "test") for r in recs)
