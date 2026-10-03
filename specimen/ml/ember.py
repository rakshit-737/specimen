"""EMBER-style static gate: vectoriser, LightGBM model, TreeSHAP explanations,
and a faithful port of the original hand-weighted heuristic (the baseline).

The vectoriser follows the EMBER v2 feature groups (byte histogram, byte-
entropy histogram, strings, general, header, sections, imports, exports,
data directories) with the hashing trick, plus a block of *named* indicator
features (notable API imports, packer section names) so explanations stay
readable.
"""
from __future__ import annotations

import json
import math
import zlib
from pathlib import Path
from typing import Any

import numpy as np

from ..static_triage import BIAS, PACKER_MARKERS, SUSPICIOUS_APIS

NOTABLE_APIS = sorted({
    *SUSPICIOUS_APIS, "VirtualAlloc", "VirtualProtect", "LoadLibraryA", "GetProcAddress",
    "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "OpenProcess",
    "ReadProcessMemory", "ResumeThread", "SetThreadContext", "GetThreadContext", "CryptAcquireContextA",
    "CryptDecrypt", "CryptGenKey", "InternetOpenA", "InternetReadFile", "HttpSendRequestA",
    "WSAStartup", "connect", "socket", "RegCreateKeyExA", "RegOpenKeyExA", "CreateServiceA",
    "OpenSCManagerA", "AdjustTokenPrivileges", "GetTickCount", "Sleep", "FindFirstFileA",
    "GetForegroundWindow", "GetKeyboardState", "OpenClipboard", "CreateToolhelp32Snapshot",
})
PACKER_NAMES = sorted({m.lower() for m in PACKER_MARKERS} | {".packed", ".themida", ".vmp0", ".vmp1",
                                                              "petite", ".nsp0", ".adata", "pec2"})

def _hash(n: int, items: list[str]) -> np.ndarray:
    """Hashing trick (CRC32 buckets, counts)."""
    v = np.zeros(n)
    for it in items:
        v[zlib.crc32(it.encode("utf-8", "replace")) % n] += 1.0
    return v


def _hash_pairs(n: int, pairs: list[tuple[str, float]]) -> np.ndarray:
    v = np.zeros(n)
    for k, val in pairs:
        v[zlib.crc32(str(k).encode("utf-8", "replace")) % n] += val
    return v


def _norm(v: list[float]) -> np.ndarray:
    a = np.asarray(v, dtype=np.float64)
    s = a.sum()
    return a / s if s else a


def _imports(row: dict[str, Any]) -> dict[str, list[str]]:
    imp = row.get("imports") or {}
    return imp if isinstance(imp, dict) else {}


def feature_groups() -> list[tuple[str, int]]:
    """``(group, width)`` of every block of the 2,440-dimension EMBER feature vector."""
    return [("histogram", 256), ("byteentropy", 256), ("strings", 104), ("general", 10),
            ("header", 62), ("section", 255), ("imports", 1280), ("exports", 128),
            ("datadirectories", 30), ("named", len(NOTABLE_APIS) + len(PACKER_NAMES) + 1)]


def feature_names() -> list[str]:
    """Human-readable name of every feature (used in TreeSHAP explanations)."""
    names: list[str] = []
    names += [f"histogram[{i}]" for i in range(256)]
    names += [f"byteentropy[{i}]" for i in range(256)]
    names += ["strings.numstrings", "strings.avlength", "strings.printables"]
    names += [f"strings.printabledist[{i}]" for i in range(96)]
    names += ["strings.entropy", "strings.paths", "strings.urls", "strings.registry", "strings.MZ"]
    names += ["general." + k for k in ("size", "vsize", "has_debug", "exports", "imports", "has_relocations",
                                       "has_resources", "has_signature", "has_tls", "symbols")]
    names += ["header.coff.timestamp"] + [f"header.machine#{i}" for i in range(10)]
    names += [f"header.characteristics#{i}" for i in range(10)] + [f"header.subsystem#{i}" for i in range(10)]
    names += [f"header.dll_characteristics#{i}" for i in range(10)] + [f"header.magic#{i}" for i in range(10)]
    names += ["header." + k for k in ("major_image_version", "minor_image_version", "major_linker_version",
                                      "minor_linker_version", "major_operating_system_version",
                                      "minor_operating_system_version", "major_subsystem_version",
                                      "minor_subsystem_version", "sizeof_code", "sizeof_headers",
                                      "sizeof_heap_commit")]
    names += ["section.count", "section.n_zero_size", "section.n_empty_name", "section.n_rx", "section.n_w"]
    names += [f"section.size#{i}" for i in range(50)] + [f"section.entropy#{i}" for i in range(50)]
    names += [f"section.vsize#{i}" for i in range(50)] + [f"section.entry_name#{i}" for i in range(50)]
    names += [f"section.entry_props#{i}" for i in range(50)]
    names += [f"imports.library#{i}" for i in range(256)] + [f"imports.function#{i}" for i in range(1024)]
    names += [f"exports#{i}" for i in range(128)]
    names += [f"datadir[{i // 2}].{'size' if i % 2 == 0 else 'va'}" for i in range(30)]
    names += [f"imports:{a}" for a in NOTABLE_APIS] + [f"section:{p}" for p in PACKER_NAMES]
    names += ["file_entropy"]
    return names


def file_entropy(row: dict[str, Any]) -> float:
    """Whole-file Shannon entropy (bits per byte) from an EMBER byte histogram."""
    h = _norm(row.get("histogram") or [0] * 256)
    nz = h[h > 0]
    return float(-(nz * np.log2(nz)).sum()) if nz.size else 0.0


def vectorize(row: dict[str, Any]) -> np.ndarray:
    """EMBER raw-feature JSON row -> fixed 2,440-dimension float32 vector (CRC32-hashed imports/exports/sections plus named API and packer flags)."""
    parts: list[np.ndarray] = []
    parts.append(_norm(row.get("histogram") or [0] * 256))
    parts.append(_norm(row.get("byteentropy") or [0] * 256))
    s = row.get("strings") or {}
    pd = s.get("printabledist") or [0] * 96
    parts.append(np.asarray([s.get("numstrings", 0), s.get("avlength", 0), s.get("printables", 0),
                             *(_norm(pd) if s.get("printables") else np.zeros(96)),
                             s.get("entropy", 0), s.get("paths", 0), s.get("urls", 0), s.get("registry", 0),
                             s.get("MZ", 0)], dtype=np.float64))
    g = row.get("general") or {}
    parts.append(np.asarray([g.get(k, 0) for k in ("size", "vsize", "has_debug", "exports", "imports",
                                                     "has_relocations", "has_resources", "has_signature",
                                                     "has_tls", "symbols")], dtype=np.float64))
    h = row.get("header") or {}
    coff, opt = h.get("coff") or {}, h.get("optional") or {}
    parts.append(np.concatenate([
        [coff.get("timestamp", 0)], _hash(10, [str(coff.get("machine", ""))]),
        _hash(10, [str(c) for c in coff.get("characteristics") or []]),
        _hash(10, [str(opt.get("subsystem", ""))]),
        _hash(10, [str(c) for c in opt.get("dll_characteristics") or []]),
        _hash(10, [str(opt.get("magic", ""))]),
        [opt.get(k, 0) for k in ("major_image_version", "minor_image_version", "major_linker_version",
                                 "minor_linker_version", "major_operating_system_version",
                                 "minor_operating_system_version", "major_subsystem_version",
                                 "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit")],
    ]))
    sec = row.get("section") or {}
    sections = [x for x in sec.get("sections") or [] if isinstance(x, dict)]
    entry = str(sec.get("entry", ""))
    entry_props = next((x.get("props") or [] for x in sections if x.get("name") == entry), [])
    parts.append(np.concatenate([
        [len(sections), sum(x.get("size", 0) == 0 for x in sections), sum(x.get("name", "") == "" for x in sections),
         sum("MEM_READ" in (x.get("props") or []) and "MEM_EXECUTE" in (x.get("props") or []) for x in sections),
         sum("MEM_WRITE" in (x.get("props") or []) for x in sections)],
        _hash_pairs(50, [(x.get("name", ""), float(x.get("size", 0))) for x in sections]),
        _hash_pairs(50, [(x.get("name", ""), float(x.get("entropy", 0))) for x in sections]),
        _hash_pairs(50, [(x.get("name", ""), float(x.get("vsize", 0))) for x in sections]),
        _hash(50, [entry]), _hash(50, [str(p) for p in entry_props]),
    ]))
    imp = _imports(row)
    libs = [lib.lower() for lib in imp]
    funcs = [f"{lib.lower()}:{f}" for lib, fs in imp.items() for f in (fs or [])]
    parts.append(np.concatenate([_hash(256, libs), _hash(1024, funcs)]))
    parts.append(_hash(128, [str(e) for e in row.get("exports") or []]))
    dd = [x for x in row.get("datadirectories") or [] if isinstance(x, dict)][:15]
    v = np.zeros(30)
    for i, d in enumerate(dd):
        v[2 * i], v[2 * i + 1] = d.get("size", 0), d.get("virtual_address", 0)
    parts.append(v)
    allf = {f.split("@")[0] for fs in imp.values() for f in (fs or [])}
    allf_l = {f.lower() for f in allf}
    named = [float(any(f.lower().startswith(a.lower()) for f in allf_l)) if a in SUSPICIOUS_APIS
             else float(a.lower() in allf_l) for a in NOTABLE_APIS]
    secnames = {str(x.get("name", "")).lower() for x in sections}
    named += [float(p in secnames) for p in PACKER_NAMES]
    named.append(file_entropy(row))
    parts.append(np.asarray(named))
    return np.concatenate(parts).astype(np.float32)


# ---------------------------------------------------------------------------
# the original MVP heuristic gate, ported to EMBER raw features (baseline)
# ---------------------------------------------------------------------------

def heuristic_score(row: dict[str, Any]) -> float:
    """``static_triage.triage`` re-expressed on EMBER raw features: same
    weights, same bias. Byte-string checks become import / section-name
    checks; whole-file entropy comes from the byte histogram."""
    imp = {f.lower() for fs in _imports(row).values() for f in (fs or [])}
    logit = BIAS + 0.8  # every EMBER sample is a PE
    for api, w in SUSPICIOUS_APIS.items():
        if any(f.startswith(api.lower()) for f in imp):
            logit += w
    secnames = {str(x.get("name", "")) for x in (row.get("section") or {}).get("sections") or []}
    if any(m in secnames for m in PACKER_MARKERS):
        logit += 0.7
    ent = file_entropy(row)
    if ent > 7.2:
        logit += 2.0 * (ent - 7.2)
    if (row.get("strings") or {}).get("urls"):
        logit += 0.3 * min((row.get("strings") or {}).get("urls", 0), 3)
    return 1 / (1 + math.exp(-logit))


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------

class StaticModel:
    """LightGBM wrapper with a calibrated detonation threshold and
    TreeSHAP (``pred_contrib``) explanations."""

    def __init__(self, booster: Any, threshold: float, meta: dict[str, Any]) -> None:
        self.booster = booster
        self.threshold = threshold
        self.meta = meta
        self.names = feature_names()

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Malicious probability for each row of ``X``."""
        return self.booster.predict(X)

    def explain(self, x: np.ndarray, k: int = 8) -> list[tuple[str, float]]:
        """Top ``k`` TreeSHAP contributions ``(feature, value)`` for one vector."""
        contrib = self.booster.predict(x.reshape(1, -1), pred_contrib=True)[0][:-1]
        idx = np.argsort(-np.abs(contrib))[:k]
        return [(self.names[i], round(float(contrib[i]), 4)) for i in idx if contrib[i]]

    def save(self, path: Path) -> None:
        """Write ``static_lgbm.txt`` (LightGBM text model) and ``static_meta.json`` (meta + threshold)."""
        path.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(path / "static_lgbm.txt"))
        (path / "static_meta.json").write_text(json.dumps({**self.meta, "threshold": self.threshold}, indent=2))

    @classmethod
    def load(cls, path: Path) -> StaticModel:
        """Load a model written by :meth:`save` (text formats only, no pickle)."""
        import lightgbm as lgb
        meta = json.loads((path / "static_meta.json").read_text())
        return cls(lgb.Booster(model_file=str(path / "static_lgbm.txt")), meta["threshold"], meta)


def train(X: np.ndarray, y: np.ndarray, seed: int = 0, rounds: int = 600) -> Any:
    """Train the LightGBM gate (binary objective, fixed hyperparameters, ``rounds`` boosting rounds)."""
    import lightgbm as lgb
    params = {"objective": "binary", "learning_rate": 0.05, "num_leaves": 64, "min_data_in_leaf": 20,
              "feature_fraction": 0.5, "bagging_fraction": 0.8, "bagging_freq": 1, "seed": seed,
              "verbose": -1, "num_threads": 8}
    return lgb.train(params, lgb.Dataset(X, y), num_boost_round=rounds)
