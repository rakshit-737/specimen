"""Behavior-trace ingestion from *recorded or synthetic* sandbox output.

SPECIMEN's MVP never detonates anything. It replays a JSON trace (a
normalized Sysmon/eBPF-style event log) captured elsewhere in an isolated lab.
"""
from __future__ import annotations

import json
from pathlib import Path

from .hashing import sha256_bytes
from .models import EVENT_TYPES, Event, Trace

MAX_EVENTS = 100_000


class TraceError(ValueError):
    pass


def parse_trace(raw: bytes) -> Trace:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise TraceError(f"invalid JSON: {e}") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("events"), list):
        raise TraceError("trace must be an object with an 'events' list")
    if len(doc["events"]) > MAX_EVENTS:
        raise TraceError("too many events")
    events: list[Event] = []
    for i, e in enumerate(doc["events"]):
        if not isinstance(e, dict):
            raise TraceError(f"event {i} is not an object")
        if e.get("type") not in EVENT_TYPES:
            raise TraceError(f"event {i}: unknown type {e.get('type')!r}")
        try:
            known = {"ts", "type", "pid", "ppid", "image", "target", "cmdline"}
            events.append(Event(
                ts=float(e["ts"]), type=e["type"], pid=int(e["pid"]),
                image=str(e["image"]),
                ppid=int(e["ppid"]) if e.get("ppid") is not None else None,
                target=e.get("target"), cmdline=e.get("cmdline"),
                extra={k: v for k, v in e.items() if k not in known},
            ))
        except (KeyError, TypeError, ValueError) as ex:
            raise TraceError(f"event {i}: {ex}") from ex
    events.sort(key=lambda ev: ev.ts)
    return Trace(str(doc.get("run_id", "unknown")), str(doc.get("sample_sha256", "")),
                 str(doc.get("sandbox", "recorded")), events, sha256_bytes(raw))


def load_trace(path: str | Path) -> Trace:
    return parse_trace(Path(path).read_bytes())
