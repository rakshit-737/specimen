"""Static triage gate: explainable additive scoring -> detonate yes/no.

The sample is only ever *read* as bytes. It is never executed.
"""
from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

from .coerce import finite_float
from .models import Contribution, Sample, StaticVerdict

MAX_BYTES = 50 * 1024 * 1024

SUSPICIOUS_APIS = {
    "VirtualAllocEx": 0.9, "WriteProcessMemory": 0.9, "CreateRemoteThread": 1.0,
    "NtUnmapViewOfSection": 1.0, "SetWindowsHookEx": 0.6, "GetAsyncKeyState": 0.6,
    "IsDebuggerPresent": 0.4, "URLDownloadToFile": 0.8, "WinExec": 0.5,
    "CryptEncrypt": 0.5, "RegSetValueEx": 0.3, "InternetOpenUrl": 0.5,
}
SUSPICIOUS_TOKENS = {
    r"CurrentVersion\\Run": 0.8, "vssadmin delete shadows": 1.2, "powershell -enc": 1.0,
    "bcdedit /set": 0.8, "schtasks /create": 0.6, "YOUR FILES HAVE BEEN ENCRYPTED": 1.5,
}
PACKER_MARKERS = {"UPX0": 0.7, "UPX1": 0.7, ".aspack": 0.7, "MPRESS1": 0.7}

URL_RE = re.compile(rb"https?://[\w.\-/:%?=&]{4,200}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
STR_RE = re.compile(rb"[\x20-\x7e]{5,}")

BIAS = -2.0
DETONATE_THRESHOLD = 0.35


def load_sample(path: str | Path) -> tuple[Sample, bytes]:
    """Hash the *whole* file (streaming) and read at most ``MAX_BYTES`` for analysis.

    :param path: sample path; the file is only read, never executed.
    :returns: the sample record (full-file SHA-256/MD5/size) and the analysed prefix.
    """
    p = Path(path)
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    with open(p, "rb") as f:
        data = f.read(MAX_BYTES)
        sha.update(data)
        md5.update(data)
        size = len(data)
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return Sample(str(p), sha.hexdigest(), md5.hexdigest(), size,
                  len(data) if size > len(data) else None), data


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def extract_strings(data: bytes, limit: int = 2000) -> list[str]:
    return [m.group().decode("ascii") for m in STR_RE.finditer(data)][:limit]


def triage(data: bytes) -> StaticVerdict:
    strings = extract_strings(data)
    blob = "\n".join(strings)
    reasons: list[Contribution] = []
    is_pe = data[:2] == b"MZ"
    ent = shannon_entropy(data)

    for api, w in SUSPICIOUS_APIS.items():
        if api in blob:
            reasons.append(Contribution(f"api:{api}", 1.0, w))
    for tok, w in SUSPICIOUS_TOKENS.items():
        if re.search(tok, blob, re.IGNORECASE):
            reasons.append(Contribution(f"token:{tok}", 1.0, w))
    for mark, w in PACKER_MARKERS.items():
        if mark in blob:
            reasons.append(Contribution(f"packer:{mark}", 1.0, w))
            break
    if ent > 7.2:
        reasons.append(Contribution("high_entropy", round(ent - 7.2, 3), 2.0))
    if is_pe:
        reasons.append(Contribution("pe_executable", 1.0, 0.8))

    urls = sorted({u.decode(errors="ignore") for u in URL_RE.findall(data)})
    ips = sorted({i.decode() for i in IP_RE.findall(data)
                  if all(0 <= int(o) <= 255 for o in i.split(b"."))})
    if urls:
        reasons.append(Contribution("embedded_urls", min(len(urls), 3), 0.3))

    logit = BIAS + sum(c.impact for c in reasons)
    score = 1 / (1 + math.exp(-logit))
    label = "malicious" if score >= 0.8 else "suspicious" if score >= DETONATE_THRESHOLD else "benign"
    # Gate: detonate anything not clearly benign, and every PE (behavior may be hidden).
    detonate = score >= DETONATE_THRESHOLD or is_pe
    reasons.sort(key=lambda c: -abs(c.impact))
    return StaticVerdict(round(score, 4), label, detonate, reasons, strings,
                         {"urls": urls, "ips": ips}, round(ent, 4), is_pe)


def triage_pe_metadata(pe: dict, sha256: str = "") -> StaticVerdict:
    """Static gate for *report-only* analysis: the same additive, explainable
    scoring applied to a sandbox's parsed PE metadata (CAPE ``static.pe``)
    instead of raw bytes. Used when only the report is available."""
    reasons: list[Contribution] = []
    imports = {str(f.get("name", "")).lower()
               for d in pe.get("imports") or [] if isinstance(d, dict)
               for f in d.get("imports") or [] if isinstance(f, dict)}
    for api, w in SUSPICIOUS_APIS.items():
        if any(i.startswith(api.lower()) for i in imports):
            reasons.append(Contribution(f"api:{api}", 1.0, w))
    names = {str(s.get("name", "")) for s in pe.get("sections") or [] if isinstance(s, dict)}
    for mark, w in PACKER_MARKERS.items():
        if mark in names:
            reasons.append(Contribution(f"packer:{mark}", 1.0, w))
            break
    ents = []
    for s in pe.get("sections") or []:
        if isinstance(s, dict):  # NaN, Infinity and non-numbers count as 0
            ents.append(finite_float(s.get("entropy", 0), 0.0, 0.0, 8.0))
    ent = max(ents, default=0.0)
    if ent > 7.2:
        reasons.append(Contribution("high_section_entropy", round(ent - 7.2, 3), 2.0))
    if len(imports) < 10:
        reasons.append(Contribution("few_imports", 1.0, 0.6))
    reasons.append(Contribution("pe_executable", 1.0, 0.8))
    logit = BIAS + sum(c.impact for c in reasons)
    score = 1 / (1 + math.exp(-logit))
    label = "malicious" if score >= 0.8 else "suspicious" if score >= DETONATE_THRESHOLD else "benign"
    reasons.sort(key=lambda c: -abs(c.impact))
    return StaticVerdict(round(score, 4), label, True, reasons, [], {"urls": [], "ips": []}, round(ent, 4), True)
