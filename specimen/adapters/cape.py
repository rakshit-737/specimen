"""CAPEv2 / Cuckoo JSON report -> SPECIMEN ``Trace``.

Handles three shapes of report, all *reports only* (no binaries involved):

* **full CAPEv2 / Cuckoo report** - ``behavior.processes[].calls`` with
  per-call timestamps, ``behavior.processtree`` and ``network`` sections;
* **reduced report** (Avast-CTU public dataset) - only ``behavior.summary``
  and ``static.pe``; there is no timing, so events receive a deterministic
  synthetic order and are flagged ``synthetic_ts``;
* any mix of the two (summary is used to fill gaps the call log misses).

The adapter never trusts the report: every string is coerced and truncated,
list sizes are capped and unknown shapes are ignored rather than raised on.
"""
from __future__ import annotations

import json
import ntpath
import re
from pathlib import Path
from typing import Any

from ..hashing import read_capped, sha256_bytes
from ..models import Event, Trace

MAX_STR = 512
MAX_PER_KIND = 2_000
MAX_CALLS_PER_PROCESS = 5_000
ROOT_PID = 1000

# CAPE/Cuckoo API names -> SPECIMEN event types (only calls that carry
# host-visible side effects; everything else stays an ``api_call``).
_INJECT_APIS = {
    "writeprocessmemory", "ntwritevirtualmemory", "createremotethread",
    "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread",
    "queueuserapc", "ntqueueapcthread", "setthreadcontext", "ntsetcontextthread",
    "ntmapviewofsection",
}
_REG_SET_APIS = {"regsetvalueexa", "regsetvalueexw", "ntsetvaluekey", "regsetvaluea", "regsetvaluew"}
_REG_DEL_APIS = {"regdeletevaluea", "regdeletevaluew", "regdeletekeya", "regdeletekeyw", "ntdeletekey",
                 "ntdeletevaluekey"}
_FILE_DEL_APIS = {"deletefilea", "deletefilew", "ntdeletefile"}
_SERVICE_APIS = {"createservicea", "createservicew"}
_MUTEX_APIS = {"ntcreatemutant", "createmutexa", "createmutexw", "createmutexexa", "createmutexexw"}

_EXE_RE = re.compile(r'^\s*"?([^"]+?\.(?:exe|com|bat|cmd|scr|dll|ps1|vbs|js))"?(?:\s|$)', re.I)


class CapeFormatError(ValueError):
    pass


def _s(v: Any) -> str:
    return str(v)[:MAX_STR] if v is not None else ""


def _list(v: Any, cap: int = MAX_PER_KIND) -> list[Any]:
    return list(v)[:cap] if isinstance(v, (list, tuple)) else []


def _args(call: dict[str, Any]) -> dict[str, str]:
    """CAPE stores arguments as a list of {name, value}; Cuckoo as a dict."""
    a = call.get("arguments")
    if isinstance(a, dict):
        return {str(k).lower(): _s(v) for k, v in a.items()}
    out: dict[str, str] = {}
    for item in _list(a, 64):
        if isinstance(item, dict) and "name" in item:
            out[str(item["name"]).lower()] = _s(item.get("value"))
    return out


def command_image(cmd: str) -> str:
    """Best-effort executable basename from a command line."""
    m = _EXE_RE.match(cmd or "")
    path = m.group(1) if m else (cmd or "").strip().strip('"').split(" ")[0]
    return ntpath.basename(path.strip('"')) or "unknown"


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _int(v: Any, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _first(d: dict[str, str], *keys: str) -> str:
    for k in keys:
        if d.get(k):
            return d[k]
    return ""


def _from_calls(report: dict[str, Any], sample_image: str) -> list[Event]:
    beh = report.get("behavior") or {}
    procs = [p for p in _list(beh.get("processes")) if isinstance(p, dict)]
    if not procs:
        return []
    evs: list[Event] = []
    t0 = None
    for p in procs:
        for c in _list(p.get("calls"), 1)[:1]:
            ts = c.get("timestamp") if isinstance(c, dict) else None
            if isinstance(ts, (int, float)):
                t0 = ts if t0 is None else min(t0, ts)
    known = {_int(p.get("process_id"), -1) for p in procs}

    def rel(ts: Any, fallback: float) -> float:
        if isinstance(ts, (int, float)) and t0 is not None:
            return max(0.0, float(ts) - t0)
        return fallback

    for idx, p in enumerate(procs):
        pid = _int(p.get("process_id"), ROOT_PID + idx)
        ppid = _int(p.get("parent_id"), 0)
        image = _s(p.get("process_name")) or sample_image
        if ppid in known:
            parent = next(q for q in procs if _int(q.get("process_id"), -1) == ppid)
            evs.append(Event(rel(None, idx * 1e-3), "process_create", ppid,
                             _s(parent.get("process_name")) or "?", target=image,
                             cmdline=_s(_dict(p.get("environ")).get("CommandLine")) or None,
                             extra={"child_pid": pid}))
        for j, c in enumerate(_list(p.get("calls"), MAX_CALLS_PER_PROCESS)):
            if not isinstance(c, dict):
                continue
            api = _s(c.get("api"))
            low = api.lower()
            a = _args(c)
            ts = rel(c.get("timestamp"), idx + j * 1e-4)
            if low in _INJECT_APIS:
                tpid = _first(a, "processid", "process_identifier", "pid")
                evs.append(Event(ts, "process_inject", pid, image, target=f"pid {tpid}" if tpid else "unknown",
                                 extra={"api": api, "target_pid": int(tpid) if tpid.isascii() and tpid.isdigit() else -1}))
            elif low in _REG_SET_APIS:
                evs.append(Event(ts, "registry_set", pid, image,
                                 target=_first(a, "fullname", "regkey", "keyname", "valuename") or "?",
                                 extra={"api": api}))
            elif low in _REG_DEL_APIS:
                evs.append(Event(ts, "registry_delete", pid, image,
                                 target=_first(a, "fullname", "regkey", "keyname") or "?", extra={"api": api}))
            elif low in _FILE_DEL_APIS:
                evs.append(Event(ts, "file_delete", pid, image,
                                 target=_first(a, "filename", "filepath") or "?", extra={"api": api}))
            elif low in _SERVICE_APIS:
                evs.append(Event(ts, "service_create", pid, image,
                                 target=_first(a, "servicename", "binarypathname") or "?", extra={"api": api}))
            elif low in _MUTEX_APIS:
                evs.append(Event(ts, "mutex_create", pid, image,
                                 target=_first(a, "mutantname", "mutexname") or "?", extra={"api": api}))
            else:
                evs.append(Event(ts, "api_call", pid, image, target=api, extra={"category": _s(c.get("category"))}))
    return evs


def _from_summary(report: dict[str, Any], sample_image: str, start: float) -> list[Event]:
    s = ((report.get("behavior") or {}).get("summary")) or {}
    if not isinstance(s, dict):
        return []
    evs: list[Event] = []
    t = start
    flag = {"synthetic_ts": True}

    def add(etype: str, target: str, **kw: Any) -> None:
        nonlocal t
        t += 1e-3
        evs.append(Event(round(t, 6), etype, kw.pop("pid", ROOT_PID), kw.pop("image", sample_image),
                         target=target, extra={**flag, **kw.pop("extra", {})}, **kw))

    for m in _list(s.get("mutexes")):
        add("mutex_create", _s(m))
    for i, cmd in enumerate(_list(s.get("executed_commands"))):
        cmd = _s(cmd)
        add("process_create", command_image(cmd), cmdline=cmd, extra={"child_pid": ROOT_PID + 1 + i})
    read = {str(f).lower() for f in _list(s.get("read_files"))}
    written = {str(f).lower() for f in _list(s.get("write_files"))} | {
        str(f).lower() for f in _list(s.get("delete_files"))}
    for f in _list(s.get("read_files")):
        add("file_read", _s(f))
    # ``files`` = every file handle opened; keep the ones not already typed
    for f in _list(s.get("files")):
        if str(f).lower() not in read and str(f).lower() not in written:
            add("file_read", _s(f), extra={"opened_only": True})
    for f in _list(s.get("write_files")):
        add("file_write", _s(f))
    for f in _list(s.get("delete_files")):
        add("file_delete", _s(f))
    for k in _list(s.get("write_keys")):
        add("registry_set", _s(k))
    for k in _list(s.get("delete_keys")):
        add("registry_delete", _s(k))
    rkeys = {str(k).lower() for k in _list(s.get("read_keys"))} | {
        str(k).lower() for k in _list(s.get("write_keys"))} | {str(k).lower() for k in _list(s.get("delete_keys"))}
    for k in _list(s.get("read_keys")):
        add("registry_read", _s(k))
    for k in _list(s.get("keys")):
        if str(k).lower() not in rkeys:
            add("registry_read", _s(k), extra={"opened_only": True})
    for svc in _list(s.get("created_services")):
        add("service_create", _s(svc))
    for svc in _list(s.get("started_services")):
        add("service_start", _s(svc))
    for api in _list(s.get("resolved_apis")):
        add("api_call", _s(api), extra={"resolved_only": True})
    return evs


def _from_network(report: dict[str, Any], sample_image: str, start: float) -> list[Event]:
    net = report.get("network") or {}
    if not isinstance(net, dict):
        return []
    evs: list[Event] = []
    t = start
    for d in _list(net.get("dns")):
        if isinstance(d, dict) and d.get("request"):
            t += 1e-3
            evs.append(Event(t, "dns_query", ROOT_PID, sample_image, target=_s(d["request"]),
                             extra={"synthetic_ts": True}))
    for proto in ("tcp", "udp"):
        seen = set()
        for c in _list(net.get(proto)):
            if isinstance(c, dict) and c.get("dst"):
                key = f"{_s(c['dst'])}:{_s(c.get('dport'))}"
                if key in seen:
                    continue
                seen.add(key)
                t += 1e-3
                evs.append(Event(t, "net_connect", ROOT_PID, sample_image, target=key,
                                 extra={"proto": proto, "synthetic_ts": True}))
    return evs


def cape_to_trace(report: dict[str, Any], run_id: str | None = None, raw: bytes | None = None) -> Trace:
    """Convert a CAPE/Cuckoo report (full call log or reduced summary) into a :class:`Trace`.

    :param report: parsed JSON report; unknown shapes are ignored, not raised on.
    :param run_id: run identifier (defaults to the report's ``info.id``).
    :param raw: original bytes, hashed into ``Trace.source_sha256``.
    :raises CapeFormatError: if the object is not a report or has no behaviour.
    """
    if not isinstance(report, dict) or not isinstance(report.get("behavior", {}), dict):
        raise CapeFormatError("not a CAPE/Cuckoo report object")
    target = _dict(_dict(report.get("target")).get("file"))
    sha = _s(target.get("sha256"))
    sample_image = _s(target.get("name")) or "sample.exe"
    events = _from_calls(report, sample_image)
    has_calls = bool(events)
    last = max((e.ts for e in events), default=0.0)
    summary = _from_summary(report, sample_image, last)
    if has_calls:
        # keep summary-only facts the call log did not already express
        seen = {(e.type, (e.target or "").lower()) for e in events}
        summary = [e for e in summary if (e.type, (e.target or "").lower()) not in seen
                   and e.type not in ("api_call",)]
    events += summary
    events += _from_network(report, sample_image, max((e.ts for e in events), default=0.0))
    if not events:
        raise CapeFormatError("report contains no behavior")
    events.sort(key=lambda e: e.ts)
    info = report.get("info") or {}
    rid = run_id or _s(info.get("id")) or sha[:16] or "cape"
    return Trace(str(rid), sha, "cape-summary" if not has_calls else "cape",
                 events, sha256_bytes(raw) if raw else "")


def load_cape(path: str | Path) -> Trace:
    raw = read_capped(path)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CapeFormatError(f"invalid JSON: {e}") from e
    return cape_to_trace(doc, run_id=Path(path).stem, raw=raw)


def looks_like_cape(doc: Any) -> bool:
    return isinstance(doc, dict) and "behavior" in doc and "events" not in doc


def static_pe(report: dict[str, Any]) -> dict[str, Any]:
    """The ``static.pe`` block of a report (empty dict if absent)."""
    st = report.get("static") or {}
    pe = st.get("pe") if isinstance(st, dict) else None
    return pe if isinstance(pe, dict) else {}

