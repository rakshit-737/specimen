"""Provenance graph reconstruction + ATT&CK-mapped timeline."""
from __future__ import annotations

from collections import defaultdict

from .models import Edge, Event, Node, TimelineEntry, Trace

LOLBINS = ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "vssadmin.exe", "bcdedit.exe", "schtasks.exe")


def map_technique(ev: Event) -> tuple[str | None, str | None]:
    t = (ev.target or "").lower()
    c = (ev.cmdline or "").lower()
    if ev.type == "process_inject":
        return "T1055", "defense-evasion"
    if ev.type == "registry_set" and r"currentversion\run" in t:
        return "T1547.001", "persistence"
    if ev.type == "scheduled_task" or "schtasks" in c:
        return "T1053.005", "persistence"
    if ev.type == "service_create":
        return "T1543.003", "persistence"
    if "vssadmin" in c and "delete" in c or "bcdedit" in c:
        return "T1490", "impact"
    if ev.type == "process_create" and ("powershell" in c and ("-enc" in c or "iex" in c)):
        return "T1059.001", "execution"
    if ev.type == "process_create" and "cmd.exe" in (ev.target or "").lower():
        return "T1059.003", "execution"
    if ev.type == "file_write" and t.endswith((".locked", ".encrypted", ".crypt")):
        return "T1486", "impact"
    if ev.type == "file_delete":
        return "T1070.004", "defense-evasion"
    if ev.type == "net_connect":
        return "T1071", "command-and-control"
    if ev.type == "dns_query":
        return "T1071.004", "command-and-control"
    if ev.type == "file_write" and t.endswith((".exe", ".dll", ".ps1", ".vbs")):
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
            label = n.label.replace('"', "'")[:60]
            lines.append(f'  {ids[nid]}["{n.kind}: {label}"]')
        for e in self.edges:
            lines.append(f"  {ids[e.src]} -->|{e.relation}| {ids[e.dst]}")
        return "\n".join(lines)


_REL = {
    "file_write": ("file", "wrote"), "file_read": ("file", "read"),
    "file_delete": ("file", "deleted"), "registry_set": ("registry", "set"),
    "net_connect": ("network", "connected"), "dns_query": ("domain", "resolved"),
    "service_create": ("service", "created"), "scheduled_task": ("task", "scheduled"),
}


def reconstruct(trace: Trace) -> tuple[ProvenanceGraph, list[TimelineEntry]]:
    g = ProvenanceGraph()
    timeline: list[TimelineEntry] = []
    pid_image: dict[int, str] = {}

    def proc(pid: int, image: str) -> str:
        pid_image.setdefault(pid, image)
        return g.add_node(f"proc:{pid}", "process", f"{pid_image[pid]} ({pid})")

    for ev in trace.events:
        src = proc(ev.pid, ev.image)
        if ev.type == "process_create":
            child_pid = int(ev.extra.get("child_pid", -1))
            dst = proc(child_pid, ev.target or "?")
            g.edges.append(Edge(src, dst, "spawned", ev.ts))
            desc = f"{ev.image} spawned {ev.target}" + (f" `{ev.cmdline}`" if ev.cmdline else "")
        elif ev.type == "process_inject":
            tpid = int(ev.extra.get("target_pid", -1))
            dst = proc(tpid, ev.target or "?")
            g.edges.append(Edge(src, dst, "injected", ev.ts))
            desc = f"{ev.image} injected into {ev.target}"
        else:
            kind, rel = _REL[ev.type]
            dst = g.add_node(f"{kind}:{ev.target}", kind, str(ev.target))
            g.edges.append(Edge(src, dst, rel, ev.ts))
            desc = f"{ev.image} {rel} {ev.target}"
        tech, tactic = map_technique(ev)
        timeline.append(TimelineEntry(ev.ts, desc, tech, tactic))
    return g, timeline
