"""Generate INERT lab fixtures: byte blobs that *look* suspicious to a string
scanner but contain no executable code, plus matching synthetic traces."""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from .corpus import behavior_events

INERT_NOTE = b"SPECIMEN-INERT-FIXTURE: not executable, contains no code.\x00"

SAMPLES = {
    "benign_notes.txt": (b"Meeting notes: quarterly planning. Budget review scheduled for Friday.\n" * 5, None),
    "sim_injector.bin": (
        b"MZ" + b"\x00" * 62 + INERT_NOTE +
        b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00IsDebuggerPresent\x00"
        b"http://203.0.113.66:8443/gate.php\x00c2.lab.invalid\x00SimInjectorBuildTag-7731\x00",
        ["dns", "net", "inject", "drop"]),
    "sim_bland.bin": (
        b"MZ" + b"\x00" * 62 + INERT_NOTE + b"BlandUtilityResourceTable\x00version 1.0.3\x00",
        ["enc_ps", "schtask", "drop", "runkey", "net"]),
    "sim_ransom.bin": (
        b"MZ" + b"\x00" * 62 + INERT_NOTE +
        b"CryptEncrypt\x00vssadmin delete shadows /all /quiet\x00YOUR FILES HAVE BEEN ENCRYPTED\x00"
        rb"Software\Microsoft\Windows\CurrentVersion\Run" b"\x00SimRansomNoteMarker-42\x00",
        ["vss", "encrypt", "runkey", "net"]),
}


def write_fixtures(out: str | Path) -> dict[str, tuple[Path, Path | None]]:
    out = Path(out)
    (out / "samples").mkdir(parents=True, exist_ok=True)
    (out / "traces").mkdir(parents=True, exist_ok=True)
    res: dict[str, tuple[Path, Path | None]] = {}
    for name, (blob, tags) in SAMPLES.items():
        sp = out / "samples" / name
        sp.write_bytes(blob)
        tp = None
        if tags:
            rng = random.Random(name)
            evs = [{"ts": 0.0, "type": "file_read", "pid": 200, "image": "sample.exe",
                    "target": r"C:\Windows\System32\config.ini"}]
            for e in behavior_events(tags, rng, 1.0):
                d = {"ts": round(e.ts, 3), "type": e.type, "pid": e.pid, "image": e.image,
                     "target": e.target, "cmdline": e.cmdline}
                d.update(e.extra)
                evs.append(d)
            tp = out / "traces" / (name.rsplit(".", 1)[0] + ".trace.json")
            tp.write_text(json.dumps({"run_id": f"lab-{name}", "sandbox": "synthetic-replay",
                                      "sample_sha256": hashlib.sha256(blob).hexdigest(),
                                      "events": evs}, indent=1))
        res[name] = (sp, tp)
    return res
