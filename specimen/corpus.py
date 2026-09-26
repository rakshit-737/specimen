"""Deterministic *synthetic* behavior corpus used to train the scorer and
provide family prototypes. No real malware data is involved."""
from __future__ import annotations

import random

from .models import Event, Trace

FAMILIES = {
    "sim-ransom": ["vss", "encrypt", "runkey", "net"],
    "sim-injector": ["inject", "net", "dns", "drop"],
    "sim-persist-loader": ["enc_ps", "schtask", "drop", "net", "runkey"],
}


def _benign_events(rng: random.Random, base: float) -> list[Event]:
    evs = []
    for i in range(rng.randint(3, 10)):
        kind = rng.choice(["file_read", "file_write", "dns_query", "net_connect", "file_read"])
        tgt = {
            "file_read": rf"C:\Users\lab\Documents\doc{i}.txt",
            "file_write": rf"C:\Users\lab\AppData\Local\app\cache{i}.dat",
            "dns_query": "updates.example.com",
            "net_connect": "198.51.100.10:443",
        }[kind]
        evs.append(Event(base + i, kind, 100, "app.exe", target=tgt))
    return evs


def behavior_events(tags: list[str], rng: random.Random, base: float = 0.0) -> list[Event]:
    evs: list[Event] = []
    t = base
    for tag in tags:
        t += rng.uniform(0.1, 2.0)
        if tag == "vss":
            evs.append(Event(t, "process_create", 200, "sample.exe", target="vssadmin.exe",
                             cmdline="vssadmin delete shadows /all /quiet", extra={"child_pid": 201}))
        elif tag == "encrypt":
            for k in range(rng.randint(3, 6)):
                evs.append(Event(t + k * 0.01, "file_write", 200, "sample.exe",
                                 target=rf"C:\Users\lab\Documents\f{k}.docx.locked"))
        elif tag == "runkey":
            evs.append(Event(t, "registry_set", 200, "sample.exe",
                             target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\updater"))
        elif tag == "net":
            evs.append(Event(t, "net_connect", 200, "sample.exe", target="203.0.113.66:8443"))
        elif tag == "dns":
            evs.append(Event(t, "dns_query", 200, "sample.exe", target="c2.lab.invalid"))
        elif tag == "inject":
            evs.append(Event(t, "process_inject", 200, "sample.exe", target="explorer.exe",
                             extra={"target_pid": 50}))
        elif tag == "drop":
            evs.append(Event(t, "file_write", 200, "sample.exe", target=r"C:\Users\lab\AppData\Roaming\svc.exe"))
        elif tag == "enc_ps":
            evs.append(Event(t, "process_create", 200, "sample.exe", target="powershell.exe",
                             cmdline="powershell -enc SQBFAFgA", extra={"child_pid": 202}))
        elif tag == "schtask":
            evs.append(Event(t, "scheduled_task", 200, "sample.exe", target=r"\Updater"))
    return evs


def synthetic_corpus(n: int = 120, seed: int = 7) -> list[tuple[Trace, int, str | None]]:
    rng = random.Random(seed)
    out: list[tuple[Trace, int, str | None]] = []
    fams = list(FAMILIES)
    for i in range(n):
        if i % 2 == 0:
            out.append((Trace(f"benign-{i}", "", "synthetic", _benign_events(rng, 0.0)), 0, None))
        else:
            fam = fams[i % len(fams)]
            tags = [t for t in FAMILIES[fam] if rng.random() > 0.15] or FAMILIES[fam][:1]
            evs = _benign_events(rng, 0.0)[:2] + behavior_events(tags, rng, 5.0)
            out.append((Trace(f"{fam}-{i}", "", "synthetic", evs), 1, fam))
    return out
