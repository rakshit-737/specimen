"""Behavior-trace ingestion from *recorded or synthetic* sandbox output.

SPECIMEN's MVP never detonates anything. It replays a JSON trace (a
normalized Sysmon/eBPF-style event log) captured elsewhere in an isolated lab.
"""
from __future__ import annotations

import math
from pathlib import Path

from .coerce import loads
from .hashing import read_capped, sha256_bytes
from .models import EVENT_TYPES, Event, Trace

MAX_EVENTS = 100_000


class TraceError(ValueError):
    """A native trace that is not valid JSON or does not follow the trace schema."""


def _finite(v: object, what: str) -> float:
    f = float(v)  # type: ignore[arg-type]
    if not math.isfinite(f):
        raise ValueError(f"{what} must be a finite number, got {v!r}")
    return f


def parse_trace(raw: bytes) -> Trace:
    """Validate and parse a native SPECIMEN trace (``{"events": [...]}`` JSON).

    Every event needs a known ``type``, a finite ``ts`` and an integer ``pid``;
    events are sorted by time and the raw bytes' SHA-256 is kept.

    :raises TraceError: on invalid JSON, schema violations, non-finite numbers or
        more than ``MAX_EVENTS`` events.
    """
    try:
        doc = loads(raw, "trace")
    except ValueError as e:
        raise TraceError(str(e)) from e
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
                ts=_finite(e["ts"], "ts"), type=e["type"], pid=int(_finite(e["pid"], "pid")),
                image=str(e["image"]),
                ppid=int(_finite(e["ppid"], "ppid")) if e.get("ppid") is not None else None,
                target=None if e.get("target") is None else str(e["target"]),
                cmdline=None if e.get("cmdline") is None else str(e["cmdline"]),
                extra={k: v for k, v in e.items() if k not in known},
            ))
        except (KeyError, TypeError, ValueError, OverflowError) as ex:
            raise TraceError(f"event {i}: {ex}") from ex
    events.sort(key=lambda ev: ev.ts)
    return Trace(str(doc.get("run_id", "unknown")), str(doc.get("sample_sha256", "")),
                 str(doc.get("sandbox", "recorded")), events, sha256_bytes(raw))


def load_trace(path: str | Path) -> Trace:
    """Read (size-capped) and parse a native trace file; see :func:`parse_trace`."""
    return parse_trace(read_capped(path))
