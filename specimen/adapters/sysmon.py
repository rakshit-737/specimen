"""Sysmon events -> ``Trace`` (spec stage 5, capture adapter; offline only).

Accepts what you get out of a Windows lab box without extra tooling:

* XML: ``wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml`` or
  ``Get-WinEvent ... | ForEach-Object { $_.ToXml() }`` (one or many
  ``<Event>`` elements, with or without a wrapping root);
* JSON lines: one object per event with ``EventID`` plus the Sysmon field
  names (``Image``, ``TargetFilename``, ...) at the top level or under
  ``EventData`` (winlogbeat/NXLog style exports).

Binary ``.evtx`` is not parsed here (it would need a third-party parser);
export it to XML first. Parsing uses ``xml.etree`` on untrusted input, so
DTDs/entities are refused before parsing and sizes are capped.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

from ..models import Event, Trace

MAX_BYTES = 50 * 1024 * 1024
MAX_EVENTS = 200_000
_NS = re.compile(r"\{[^}]*\}")


def _pid(v: Any) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def _ts(v: Any) -> float | None:
    if not v:
        return None
    s = str(v).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:26], fmt).timestamp()
        except ValueError:
            continue
    return None


def _event(eid: int, d: dict[str, str]) -> tuple[str, dict[str, Any]] | None:
    """Map one Sysmon event (id + EventData) to (type, Event kwargs)."""
    image = d.get("Image") or d.get("SourceImage") or "?"
    pid = _pid(d.get("ProcessId") or d.get("SourceProcessId"))
    base: dict[str, Any] = {"pid": pid, "image": image, "extra": {"sysmon_id": eid}}
    if eid == 1:
        return "process_create", {"pid": _pid(d.get("ParentProcessId")), "image": d.get("ParentImage") or "?",
                                  "target": image, "cmdline": d.get("CommandLine"),
                                  "extra": {"sysmon_id": 1, "child_pid": pid}}
    if eid == 3:
        ip, port = d.get("DestinationIp") or d.get("DestinationHostname"), d.get("DestinationPort")
        return "net_connect", {**base, "target": f"{ip}:{port}" if port else ip}
    if eid == 8:
        return "process_inject", {**base, "target": f"pid {_pid(d.get('TargetProcessId'))}",
                                  "extra": {"sysmon_id": 8, "api": "CreateRemoteThread",
                                            "target_image": d.get("TargetImage")}}
    if eid in (11, 15):
        return "file_write", {**base, "target": d.get("TargetFilename")}
    if eid in (23, 26):
        return "file_delete", {**base, "target": d.get("TargetFilename")}
    if eid in (12, 13, 14):
        et = (d.get("EventType") or "").lower()
        if "delete" in et:
            return "registry_delete", {**base, "target": d.get("TargetObject")}
        if eid == 12 and "create" in et:
            return None  # key creation alone is too noisy; the SetValue that follows is kept
        return "registry_set", {**base, "target": d.get("TargetObject"),
                                "extra": {"sysmon_id": eid, "details": (d.get("Details") or "")[:256]}}
    if eid == 22:
        return "dns_query", {**base, "target": d.get("QueryName")}
    if eid == 17:
        return "mutex_create", {**base, "target": d.get("PipeName"), "extra": {"sysmon_id": 17, "pipe": True}}
    return None


def _xml_records(text: str) -> list[tuple[int, dict[str, str]]]:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("DTD/entity declarations are not accepted in Sysmon XML")
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    root = ET.fromstring(f"<Events>{body}</Events>")
    out = []
    for ev in root.iter():
        if _NS.sub("", ev.tag) != "Event":
            continue
        eid, data = 0, {}
        for el in ev.iter():
            tag = _NS.sub("", el.tag)
            if tag == "EventID":
                eid = _pid(el.text)
            elif tag == "Data" and el.get("Name"):
                data[el.get("Name")] = (el.text or "").strip()
        out.append((eid, data))
    return out


def _json_records(text: str) -> list[tuple[int, dict[str, str]]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        o = json.loads(line)
        if not isinstance(o, dict):
            continue
        data = o.get("EventData") if isinstance(o.get("EventData"), dict) else o
        out.append((_pid(o.get("EventID") or o.get("event_id")), {str(k): str(v) for k, v in data.items()}))
    return out


def sysmon_to_trace(text: str | bytes, run_id: str = "sysmon", sample_sha256: str = "") -> Trace:
    """Convert a Sysmon export (``wevtutil /f:xml`` XML or JSON lines) into a :class:`Trace`.

    :param text: export contents; DTDs are refused and size is capped.
    :param run_id: run identifier stored in the trace.
    :param sample_sha256: SHA-256 of the sample the run belongs to, if known.
    :raises ValueError: on oversized or malformed input.
    """
    if isinstance(text, bytes):
        if len(text) > MAX_BYTES:
            raise ValueError("Sysmon export too large")
        text = text.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    recs = _xml_records(text) if stripped.startswith("<") else _json_records(text)
    rows = []
    for eid, d in recs[:MAX_EVENTS]:
        m = _event(eid, d)
        if m is None or not (m[1].get("target")):
            continue
        rows.append((_ts(d.get("UtcTime")), m))
    real = [t for t, _ in rows if t is not None]
    t0 = min(real) if real else 0.0
    evs = []
    for i, (t, (etype, kw)) in enumerate(rows):
        extra = dict(kw.pop("extra", {}))
        if t is None:
            extra["synthetic_ts"] = True
        ts = round((t - t0) if t is not None else i * 1e-3, 6)
        evs.append(Event(max(ts, 0.0), etype, kw.pop("pid"), kw.pop("image"), extra=extra, **kw))
    evs.sort(key=lambda e: e.ts)
    return Trace(run_id, sample_sha256, "sysmon", evs)
