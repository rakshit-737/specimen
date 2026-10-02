"""Provenance graph reconstruction + ATT&CK-mapped timeline."""
from __future__ import annotations

from collections import defaultdict

from .escape import mermaid_label
from .models import Edge, Event, Node, TimelineEntry, Trace

LOLBINS = ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "vssadmin.exe", "bcdedit.exe", "schtasks.exe")


# API names (lower-case, without the ``dll.`` prefix CAPE puts on resolved
# APIs) that on their own indicate a technique. Kept deliberately small and
# high-signal: this feeds explainable features, not a signature engine.
API_TECHNIQUES: dict[str, tuple[str, str]] = {
    "isdebuggerpresent": ("T1622", "defense-evasion"),
    "checkremotedebuggerpresent": ("T1622", "defense-evasion"),
    "ntqueryinformationprocess": ("T1622", "defense-evasion"),
    "getasynckeystate": ("T1056.001", "collection"),
    "setwindowshookexa": ("T1056.001", "collection"),
    "setwindowshookexw": ("T1056.001", "collection"),
    "getkeyboardstate": ("T1056.001", "collection"),
    "urldownloadtofilea": ("T1105", "command-and-control"),
    "urldownloadtofilew": ("T1105", "command-and-control"),
    "internetopenurla": ("T1071.001", "command-and-control"),
    "internetopenurlw": ("T1071.001", "command-and-control"),
    "httpsendrequesta": ("T1071.001", "command-and-control"),
    "httpsendrequestw": ("T1071.001", "command-and-control"),
    "winhttpsendrequest": ("T1071.001", "command-and-control"),
    "createtoolhelp32snapshot": ("T1057", "discovery"),
    "process32firstw": ("T1057", "discovery"),
    "enumprocesses": ("T1057", "discovery"),
    "getcomputernamea": ("T1082", "discovery"),
    "getcomputernamew": ("T1082", "discovery"),
    "getnativesysteminfo": ("T1082", "discovery"),
    "cryptunprotectdata": ("T1555", "credential-access"),
    "credenumeratea": ("T1555", "credential-access"),
    "credenumeratew": ("T1555", "credential-access"),
    "cryptencrypt": ("T1486", "impact"),
    "bitblt": ("T1113", "collection"),
    "getclipboarddata": ("T1115", "collection"),
    "virtualallocex": ("T1055", "defense-evasion"),
    "writeprocessmemory": ("T1055", "defense-evasion"),
    "createremotethread": ("T1055", "defense-evasion"),
    "ntunmapviewofsection": ("T1055.012", "defense-evasion"),
    "zwunmapviewofsection": ("T1055.012", "defense-evasion"),
    "adjusttokenprivileges": ("T1134", "privilege-escalation"),
    "netshareenum": ("T1135", "discovery"),
    "wnetenumresourcew": ("T1135", "discovery"),
}

_BROWSER_CRED = (r"\login data", r"\cookies", r"\mozilla\firefox\profiles", r"\logins.json",
                 r"\key3.db", r"\key4.db", r"\web data", "\\filezilla\\", r"\outlook\profiles")
_STARTUP = ("\\start menu\\programs\\startup\\",)
_RUN_KEYS = (r"currentversion\run", r"currentversion\policies\explorer\run",
             r"currentversion\winlogon\shell", r"currentversion\winlogon\userinit")


def api_name(target: str) -> str:
    """``kernel32.dll.GetProcAddress`` -> ``getprocaddress``."""
    t = target.lower()
    if ".dll." in t:
        t = t.rsplit(".dll.", 1)[1]
    return t


def map_technique(ev: Event) -> tuple[str | None, str | None]:
    t = (ev.target or "").lower()
    c = (ev.cmdline or "").lower()
    if ev.type == "api_call":
        return API_TECHNIQUES.get(api_name(t), (None, None))
    if ev.type == "process_inject":
        return "T1055", "defense-evasion"
    if ev.type == "registry_set" and any(k in t for k in _RUN_KEYS):
        return "T1547.001", "persistence"
    if ev.type == "file_write" and any(k in t for k in _STARTUP):
        return "T1547.001", "persistence"
    if ev.type == "scheduled_task" or "schtasks" in c:
        return "T1053.005", "persistence"
    if ev.type == "service_create":
        return "T1543.003", "persistence"
    if ev.type == "service_start":
        return "T1569.002", "execution"
    if "vssadmin" in c and "delete" in c or "bcdedit" in c or "wbadmin" in c and "delete" in c:
        return "T1490", "impact"
    if ev.type == "process_create" and ("powershell" in c and ("-enc" in c or "iex" in c)):
        return "T1059.001", "execution"
    if ev.type == "process_create" and "cmd.exe" in (ev.target or "").lower():
        return "T1059.003", "execution"
    if ev.type == "process_create" and ("wscript" in t or "cscript" in t):
        return "T1059.005", "execution"
    if ev.type == "file_write" and t.endswith((".locked", ".encrypted", ".crypt")):
        return "T1486", "impact"
    if ev.type == "file_delete":
        return "T1070.004", "defense-evasion"
    if ev.type in ("file_read", "registry_read") and any(k in t for k in _BROWSER_CRED):
        return "T1555.003", "credential-access"
    if ev.type == "registry_set" and "\\policies\\" in t:
        return "T1112", "defense-evasion"
    if ev.type == "net_connect":
        return "T1071", "command-and-control"
    if ev.type == "dns_query":
        return "T1071.004", "command-and-control"
    if ev.type == "file_write" and t.endswith((".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr")):
        return "T1105", "command-and-control"
    return None, None


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add_node(self, nid: str, kind: str, label: str) -> str:
        self.nodes.setdefault(nid, Node(nid, kind, label))
        return nid

    def children(self, nid: str) -> list[Edge]:
        return [e for e in self.edges if e.src == nid]

    def roots(self) -> list[str]:
        dst = {e.dst for e in self.edges}
        return [n for n, v in self.nodes.items() if v.kind == "process" and n not in dst]

    def descendants(self, nid: str) -> set[str]:
        adj = defaultdict(list)
        for e in self.edges:
            adj[e.src].append(e.dst)
        seen, stack = set(), [nid]
        while stack:
            for nxt in adj[stack.pop()]:
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    def to_mermaid(self) -> str:
        ids = {nid: f"n{i}" for i, nid in enumerate(self.nodes)}
        lines = ["flowchart LR"]
        for nid, n in self.nodes.items():
            lines.append(f'  {ids[nid]}["{n.kind}: {mermaid_label(n.label)}"]')
        for e in self.edges:
            lines.append(f'  {ids[e.src]} -->|"{e.relation}"| {ids[e.dst]}')
        return "\n".join(lines)


def _pid(v: object) -> int:
    try:
        return int(str(v)) if str(v).lstrip("-").isascii() else -1
    except ValueError:
        return -1


_REL = {
    "file_write": ("file", "wrote"), "file_read": ("file", "read"),
    "file_delete": ("file", "deleted"), "registry_set": ("registry", "set"),
    "net_connect": ("network", "connected"), "dns_query": ("domain", "resolved"),
    "service_create": ("service", "created"), "scheduled_task": ("task", "scheduled"),
    "registry_delete": ("registry", "deleted"), "registry_read": ("registry", "read"),
    "mutex_create": ("mutex", "created"), "service_start": ("service", "started"),
    "api_call": ("api", "called"),
}


def reconstruct(trace: Trace, include_benign_apis: bool = False
                ) -> tuple[ProvenanceGraph, list[TimelineEntry]]:
    """Build the provenance graph + ATT&CK timeline.

    ``api_call`` events carry no host side effect; unless they map to a
    technique they are left out of the graph/timeline (they would otherwise
    swamp a real CAPE report with thousands of nodes)."""
    g = ProvenanceGraph()
    timeline: list[TimelineEntry] = []
    pid_image: dict[int, str] = {}

    def proc(pid: int, image: str) -> str:
        pid_image.setdefault(pid, image)
        return g.add_node(f"proc:{pid}", "process", f"{pid_image[pid]} ({pid})")

    for ev in trace.events:
        tech, tactic = map_technique(ev)
        if ev.type == "api_call" and not tech and not include_benign_apis:
            continue
        src = proc(ev.pid, ev.image)
        if ev.type == "process_create":
            child_pid = _pid(ev.extra.get("child_pid", -1))
            dst = proc(child_pid, ev.target or "?")
            g.edges.append(Edge(src, dst, "spawned", ev.ts))
            desc = f"{ev.image} spawned {ev.target}" + (f" `{ev.cmdline}`" if ev.cmdline else "")
        elif ev.type == "process_inject":
            tpid = _pid(ev.extra.get("target_pid", -1))
            dst = proc(tpid, ev.target or "?")
            g.edges.append(Edge(src, dst, "injected", ev.ts))
            desc = f"{ev.image} injected into {ev.target}"
        else:
            kind, rel = _REL[ev.type]
            dst = g.add_node(f"{kind}:{ev.target}", kind, str(ev.target))
            g.edges.append(Edge(src, dst, rel, ev.ts))
            desc = f"{ev.image} {rel} {ev.target}"
        timeline.append(TimelineEntry(ev.ts, desc, tech, tactic))
    return g, timeline
