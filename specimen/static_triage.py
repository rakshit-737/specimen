"""Static triage gate: explainable additive scoring -> detonate yes/no.

The sample is only ever *read* as bytes. It is never executed.
"""
from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

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
    p = Path(path)
    data = p.read_bytes()[:MAX_BYTES]
    return Sample(str(p), hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(), len(data)), data


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
