"""Normalised, explainable tokens from a trace (behaviour) and a CAPE
``static.pe`` block (static). Standard library only.

Tokens are the shared vocabulary of the family model, the prevalence
filter and the detection synthesizer: ``mutex:global\\m<hex>``,
``file_write:%appdata%\\<hex>.exe``, ``tech:T1547.001`` ...

Normalisation removes run-specific noise (user names, GUIDs, hex/random
blobs, numbers) so two runs of the same family share tokens.
"""
from __future__ import annotations

import ntpath
import re
from collections.abc import Iterable
from functools import lru_cache
from typing import Any

from .coerce import finite_float, safe_int
from .models import Trace
from .provenance import map_technique

_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_SID = re.compile(r"s-1-5-21-[\d-]+")
_HEX = re.compile(r"(?<![a-z])(?=[0-9a-f]*\d)[0-9a-f]{6,}(?![a-z])")
_NUM = re.compile(r"\d+")
_ENV = (
    (re.compile(r"c:\\users\\[^\\]+\\appdata\\roaming"), "%appdata%"),
    (re.compile(r"c:\\users\\[^\\]+\\appdata\\local\\temp"), "%temp%"),
    (re.compile(r"c:\\users\\[^\\]+\\appdata\\local"), "%localappdata%"),
    (re.compile(r"c:\\users\\[^\\]+"), "%userprofile%"),
    (re.compile(r"c:\\programdata"), "%programdata%"),
    (re.compile(r"c:\\windows\\(system32|syswow64)"), "%system%"),
    (re.compile(r"c:\\windows"), "%windir%"),
    (re.compile(r"hkey_current_user"), "hkcu"),
    (re.compile(r"hkey_local_machine"), "hklm"),
    (re.compile(r"hkey_users\\[^\\]+"), "hkcu"),
)
MAX_TOKENS = 4000


@lru_cache(maxsize=262_144)
def normalize(value: str) -> str:
    """Lower-case and replace run-specific parts with placeholders."""
    v = (value or "").lower().strip().strip('"')[:300]
    if "c:\\" in v or "hkey_" in v:
        for rx, rep in _ENV:
            v = rx.sub(rep, v)
    v = _GUID.sub("<guid>", v)
    v = _SID.sub("<sid>", v)
    v = _HEX.sub("<hex>", v)
    v = _NUM.sub("#", v)
    return v


def _dir(v: str) -> str:
    return ntpath.dirname(v)


def _ext(v: str) -> str:
    b = ntpath.basename(v)
    return b.rsplit(".", 1)[-1] if "." in b else ""


def behavior_tokens(trace: Trace) -> list[str]:
    """Bag of normalised behaviour tokens (set semantics, sorted)."""
    out: set[str] = set()
    for ev in trace.events:
        et = ev.type
        tech, tactic = map_technique(ev)
        if tech:
            out.add(f"tech:{tech}")
            out.add(f"tactic:{tactic}")
        if et == "api_call":
            t = (ev.target or "").lower()
            out.add("api:" + (t.rsplit(".dll.", 1)[-1] if ".dll." in t else t))
            continue
        t = normalize(ev.target or "")
        opened = ev.extra.get("opened_only")
        if et == "process_create":
            out.add(f"exec:{normalize(ev.target or '')}")
            if ev.cmdline:
                out.add(f"cmd:{normalize(ev.cmdline)[:120]}")
            continue
        if et in ("file_read", "file_write", "file_delete"):
            kind = "file_open" if opened else et
            out.add(f"{kind}:{t}")
            out.add(f"{kind}_dir:{_dir(t)}")
            if et != "file_read":
                out.add(f"{kind}_ext:{_ext(t)}")
            continue
        if et.startswith("registry_"):
            kind = "reg_open" if opened else et
            out.add(f"{kind}:{t}")
            out.add(f"{kind}_parent:{_dir(t)}")
            continue
        out.add(f"{et}:{t}")
        if len(out) > MAX_TOKENS:
            break
    return sorted(out)[:MAX_TOKENS]


def _hexint(v: Any) -> int:
    return safe_int(v, 0)


def static_tokens(pe: dict[str, Any]) -> list[str]:
    """Tokens from a CAPE ``static.pe`` block (imports, sections, header)."""
    if not pe:
        return []
    out: set[str] = set()
    if pe.get("imphash"):
        out.add(f"imphash:{pe['imphash']}")
    for d in pe.get("imports") or []:
        if not isinstance(d, dict):
            continue
        dll = str(d.get("dll", "")).lower()
        out.add(f"dll:{dll}")
        for f in (d.get("imports") or [])[:500]:
            if isinstance(f, dict) and f.get("name"):
                out.add(f"imp:{dll}:{str(f['name']).lower()}")
    for s in pe.get("sections") or []:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name", "")).strip("\x00").lower() or "<empty>"
        out.add(f"sec:{name}")
        ent = finite_float(s.get("entropy", 0), 0.0, 0.0, 8.0)  # NaN/inf/garbage -> 0
        out.add(f"sec_ent:{name}:{int(ent)}")
    out.add(f"osversion:{pe.get('osversion')}")
    out.add(f"ndll:{min(max(safe_int(pe.get('imported_dll_count'), 0), 0), 20)}")
    ts = str(pe.get("timestamp") or "")[:4]
    if ts:
        out.add(f"pe_year:{ts}")
    for e in (pe.get("exports") or [])[:50]:
        if isinstance(e, dict) and e.get("name"):
            out.add(f"exp:{str(e['name']).lower()}")
    if pe.get("digital_signers"):
        out.add("signed")
    return sorted(out)


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb) if sa | sb else 0.0
