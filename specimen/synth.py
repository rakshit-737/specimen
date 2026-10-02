"""Detection synthesis: YARA (static) + Sigma (behavioral), with a built-in
specificity check against a benign corpus."""
from __future__ import annotations

import re

from .escape import hex_or, sigma_literal, yaml_sq, yara_str
from .models import Detections, Event, StaticVerdict, Trace
from .provenance import map_technique
from .static_triage import PACKER_MARKERS, SUSPICIOUS_APIS, SUSPICIOUS_TOKENS

GENERIC = re.compile(r"^(kernel32|user32|ntdll|advapi32|msvcrt)\.dll$|^This program|^\.text$|^\.data$", re.I)


def _yara_escape(s: str) -> str:
    return yara_str(s)


def pick_yara_strings(verdict: StaticVerdict, benign_blobs: list[bytes], k: int = 6) -> list[str]:
    ranked: list[str] = []
    keys = list(SUSPICIOUS_APIS) + list(SUSPICIOUS_TOKENS) + list(PACKER_MARKERS)
    for s in verdict.strings:
        if GENERIC.search(s) or len(s) > 120:
            continue
        if any(k2.lower() in s.lower() for k2 in keys) or re.search(r"https?://|\d+\.\d+\.\d+\.\d+", s):
            ranked.append(s)
    # add longest remaining unique strings for specificity
    rest = sorted({s for s in verdict.strings if 8 <= len(s) <= 80 and s not in ranked}, key=len, reverse=True)
    ranked += rest
    chosen: list[str] = []
    for s in ranked:
        if s in chosen or any(s.encode() in b for b in benign_blobs):
            continue
        chosen.append(s)
        if len(chosen) >= k:
            break
    return chosen


def yara_rule(name: str, sha256: str, strings: list[str]) -> str | None:
    if not strings:
        return None
    body = "\n".join(f'        $s{i} = "{_yara_escape(s)}" ascii wide' for i, s in enumerate(strings))
    need = max(1, (len(strings) + 1) // 2)
    return (f"rule {name}\n{{\n    meta:\n        author = \"SPECIMEN (auto)\"\n"
            f"        sample_sha256 = \"{hex_or(sha256, 64, 'unknown')}\"\n        confidence = \"auto-generated; review before deploy\"\n"
            f"    strings:\n{body}\n    condition:\n        {need} of ($s*)\n}}\n")


def yara_matches(strings: list[str], need: int, blob: bytes) -> bool:
    hits = sum(1 for s in strings if s.encode() in blob or s.encode("utf-16-le") in blob)
    return hits >= need


# ---- Sigma ---------------------------------------------------------------

def _sigma_selection(ev: Event) -> tuple[str, dict[str, str]] | None:
    tech, _ = map_technique(ev)
    if not tech:
        return None
    if ev.type == "process_create" and ev.cmdline:
        key = ev.cmdline.split()[0]
        flag = next((w for w in ev.cmdline.split()[1:] if w.startswith(("-", "/")) or w in ("delete", "shadows")), None)
        sel = {"Image|endswith": "\\" + str(ev.target)}
        if flag:
            sel["CommandLine|contains"] = flag
        return ("process_creation", sel) if key else None
    if ev.type == "registry_set":
        return "registry_set", {"TargetObject|contains": r"\CurrentVersion\Run" + "\\"}
    if ev.type == "file_write" and tech == "T1486":
        ext = "." + (ev.target or "").rsplit(".", 1)[-1]
        return "file_event", {"TargetFilename|endswith": ext}
    if ev.type == "process_inject":
        return "create_remote_thread", {"TargetImage|endswith": "\\" + str(ev.target)}
    return None


def sigma_rules(trace: Trace, sha256: str) -> list[tuple[str, str, dict[str, str], str]]:
    seen = set()
    out = []
    for ev in trace.events:
        r = _sigma_selection(ev)
        if not r:
            continue
        cat, sel = r
        key = (cat, tuple(sorted(sel.items())))
        if key in seen:
            continue
        seen.add(key)
        tech = map_technique(ev)[0]
        sel_yaml = "\n".join(f"        {k}: {yaml_sq(sigma_literal(v))}" for k, v in sel.items())
        title = yaml_sq(f"SPECIMEN auto - {tech} via {ev.image}")
        text = (f"title: {title}\nstatus: experimental\n"
                f"description: Auto-synthesized from run of {hex_or(sha256, 64, 'unknown')[:16]}; review before deploy\n"
                f"tags:\n    - attack.{tech.lower()}\nlogsource:\n    product: windows\n    category: {cat}\n"
                f"detection:\n    selection:\n{sel_yaml}\n    condition: selection\nlevel: medium\n")
        out.append((cat, tech, sel, text))
    return out


_CAT_OF = {"process_create": "process_creation", "registry_set": "registry_set",
           "file_write": "file_event", "process_inject": "create_remote_thread"}
_FIELD = {"Image": lambda e: "\\" + (e.target or ""), "CommandLine": lambda e: e.cmdline or "",
          "TargetObject": lambda e: e.target or "", "TargetFilename": lambda e: e.target or "",
          "TargetImage": lambda e: "\\" + (e.target or "")}


def sigma_matches(cat: str, sel: dict[str, str], ev: Event) -> bool:
    if _CAT_OF.get(ev.type) != cat:
        return False
    for k, v in sel.items():
        field, op = k.split("|")
        val = _FIELD[field](ev).lower()
        if op == "endswith" and not val.endswith(v.lower()):
            return False
        if op == "contains" and v.lower() not in val:
            return False
    return True


def synthesize(verdict: StaticVerdict, sha256: str, trace: Trace | None,
               benign_blobs: list[bytes], benign_traces: list[Trace]) -> Detections:
    strs = pick_yara_strings(verdict, benign_blobs)
    rule = yara_rule(f"SPECIMEN_{sha256[:12]}", sha256, strs) if verdict.label != "benign" else None
    need = max(1, (len(strs) + 1) // 2)
    yfp = [f"benign_blob_{i}" for i, b in enumerate(benign_blobs) if rule and yara_matches(strs, need, b)]
    sigmas, sfp = [], []
    if trace is not None:
        for cat, tech, sel, text in sigma_rules(trace, sha256):
            fps = [bt.run_id for bt in benign_traces if any(sigma_matches(cat, sel, e) for e in bt.events)]
            if fps:
                sfp.extend(f"{tech}:{f}" for f in fps)
                continue  # drop non-specific rule
            sigmas.append(text)
    return Detections(rule, sigmas, yfp, sfp)
