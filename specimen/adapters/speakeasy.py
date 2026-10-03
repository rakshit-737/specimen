"""Speakeasy emulation report -> ``Trace`` (offline; reports only).

Speakeasy (Mandiant) emulates a PE instead of running it. The Quo Vadis
dataset (Trizna 2022, Apache-2.0) publishes one Speakeasy JSON report per
sample; benign samples live under ``report_clean`` and
``report_windows_syswow64``. SPECIMEN uses those benign reports to measure
how often synthesised Sigma rules fire on benign software.

Accepted shapes: a list of entry points, or an object with an
``entry_points`` list. Each entry point may carry::

    apis             [{api_name: "KERNEL32.CreateFileA", args: [...], ret_val}]
    file_access      [{event: "create"|"open"|"read"|"write"|"delete", path}]
    registry_access  [{event: "open_key"|"create_key"|"read_value"|"write_value"|..., path, value_name}]
    network_events   {dns: [{query}], traffic: [{server, port, proto}]}

Mapping (same line format as CAPE and Sysmon traces, so the same Sigma
matcher applies): process-creation APIs (``CreateProcess*``, ``WinExec``,
``ShellExecute*``) -> ``process_create``; file create/write ->
``file_write``; registry value writes -> ``registry_set``; DNS/traffic ->
``dns_query``/``net_connect``; every API call -> ``api_call``.

The input is untrusted: strings are coerced and truncated, lists capped,
unknown shapes ignored. An emulator records fewer side effects than a
sandbox, so benign false-positive rates measured on these reports are a
lower bound for sandbox traces.
"""
from __future__ import annotations

from typing import Any

from ..coerce import loads
from ..models import Event, Trace

MAX_STR = 512
MAX_EP = 256
MAX_APIS_PER_EP = 5_000
MAX_ACCESS = 2_000
ROOT_PID = 1000

_PROC_APIS = {"createprocessa", "createprocessw", "createprocessasusera", "createprocessasuserw",
              "createprocessinternala", "createprocessinternalw", "createprocesswithlogonw",
              "createprocesswithtokenw", "winexec", "shellexecutea", "shellexecutew"}


def _s(v: Any) -> str:
    return str(v)[:MAX_STR] if v is not None else ""


def _list(v: Any, cap: int) -> list[Any]:
    return list(v)[:cap] if isinstance(v, (list, tuple)) else []


def _arg(args: list[Any], i: int) -> str:
    v = _s(args[i]) if i < len(args) else ""
    # pointers / NULL are rendered as hex numbers by Speakeasy; they carry no string
    return "" if v.lower().startswith("0x") or v in ("", "None") else v


def _process_event(name: str, args: list[Any], ts: float, image: str) -> Event | None:
    low = name.lower()
    if low.startswith(("createprocessasuser", "createprocesswith")):
        app, cmd = _arg(args, 1), _arg(args, 2)
    elif low.startswith("createprocessinternal"):
        app, cmd = _arg(args, 1), _arg(args, 2)
    elif low.startswith("createprocess"):
        app, cmd = _arg(args, 0), _arg(args, 1)
    elif low == "winexec":
        app, cmd = "", _arg(args, 0)
    else:  # ShellExecuteA/W(hwnd, op, file, params, dir, show)
        app, params = _arg(args, 2), _arg(args, 3)
        cmd = f"{app} {params}".strip() if app else ""
    target = app or (cmd.split('"')[1] if cmd.startswith('"') and cmd.count('"') >= 2 else cmd.split(" ")[0])
    if not (target or cmd):
        return None
    return Event(ts, "process_create", ROOT_PID, image, target=target or None, cmdline=cmd or None,
                 extra={"api": name, "child_pid": -1})


def speakeasy_to_trace(report: Any, run_id: str = "speakeasy", raw: bytes | None = None) -> Trace:
    """Convert one Speakeasy report (list of entry points or ``{"entry_points": [...]}``) into a :class:`Trace`.

    :param report: parsed JSON (or raw bytes/str, parsed here).
    :param run_id: identifier stored in the trace (e.g. the report's file name).
    :param raw: original bytes, only used for the trace's source hash.
    :returns: a trace with ``sandbox == "speakeasy"`` and synthetic, ordered timestamps.
    :raises ValueError: if the report is not JSON or has no entry points.
    """
    from ..hashing import sha256_bytes
    if isinstance(report, (bytes, str)):
        raw = report.encode() if isinstance(report, str) else report
        report = loads(raw, "Speakeasy report")
    eps = report.get("entry_points") if isinstance(report, dict) else report
    eps = [e for e in _list(eps, MAX_EP) if isinstance(e, dict)]
    if not eps:
        raise ValueError("Speakeasy report has no entry points")
    sha = _s(report.get("sha256")) if isinstance(report, dict) else ""
    image = f"{sha[:16]}.exe" if sha else "sample.exe"
    evs: list[Event] = []
    t = 0.0

    def tick() -> float:
        nonlocal t
        t += 1e-3
        return round(t, 6)

    for ep in eps:
        for c in _list(ep.get("apis"), MAX_APIS_PER_EP):
            if not isinstance(c, dict):
                continue
            full = _s(c.get("api_name"))
            name = full.rsplit(".", 1)[-1]
            if not name:
                continue
            args = _list(c.get("args"), 16)
            ts = tick()
            evs.append(Event(ts, "api_call", ROOT_PID, image, target=name[:128], extra={"module": full[:64]}))
            if name.lower() in _PROC_APIS:
                pe = _process_event(name, args, ts, image)
                if pe is not None:
                    evs.append(pe)
        for f in _list(ep.get("file_access"), MAX_ACCESS):
            if not isinstance(f, dict) or not f.get("path"):
                continue
            ev = _s(f.get("event")).lower()
            et = ("file_write" if ("write" in ev or "create" in ev) else "file_delete" if "delete" in ev
                  else "file_read")
            evs.append(Event(tick(), et, ROOT_PID, image, target=_s(f.get("path")), extra={"speakeasy_event": ev}))
        for r in _list(ep.get("registry_access"), MAX_ACCESS):
            if not isinstance(r, dict) or not r.get("path"):
                continue
            ev = _s(r.get("event")).lower()
            path = _s(r.get("path")).rstrip("\\")
            vname = _s(r.get("value_name"))
            target = f"{path}\\{vname}" if vname else path
            if "delete" in ev:
                et = "registry_delete"
            elif ("write" in ev or "set" in ev) and "key" not in ev:
                et = "registry_set"
            elif "create" in ev:
                continue  # key creation alone is too noisy (as for Sysmon); the value write is kept
            else:
                et = "registry_read"
            evs.append(Event(tick(), et, ROOT_PID, image, target=target, extra={"speakeasy_event": ev}))
        net = ep.get("network_events") if isinstance(ep.get("network_events"), dict) else {}
        for d in _list(net.get("dns"), MAX_ACCESS):
            if isinstance(d, dict) and d.get("query"):
                evs.append(Event(tick(), "dns_query", ROOT_PID, image, target=_s(d.get("query"))))
        for tr in _list(net.get("traffic"), MAX_ACCESS):
            if isinstance(tr, dict) and tr.get("server"):
                port = _s(tr.get("port"))
                evs.append(Event(tick(), "net_connect", ROOT_PID, image,
                                 target=f"{_s(tr.get('server'))}:{port}" if port else _s(tr.get("server"))))
    for e in evs:
        e.extra.setdefault("synthetic_ts", True)
    return Trace(run_id, sha, "speakeasy", evs, sha256_bytes(raw) if raw else "")
