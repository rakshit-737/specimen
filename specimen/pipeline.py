"""Orchestration: triage -> (trace replay) -> reconstruct -> score -> synthesize -> report."""
from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from .adapters.cape import cape_to_trace, static_pe
from .corpus import synthetic_corpus
from .detect import blobs, synthesize_sigma, synthesize_yara_pe
from .hashing import sha256_bytes
from .models import Detections, Sample, Trace
from .provenance import map_technique, reconstruct
from .report import build_report
from .scoring import event_anomaly, score
from .static_triage import load_sample, triage, triage_pe_metadata
from .synth import synthesize
from .tokens import behavior_tokens, static_tokens
from .trace import load_trace

log = logging.getLogger(__name__)

DEFAULT_BENIGN_BLOBS = [
    b"MZ\x90\x00This program cannot be run in DOS mode.\x00kernel32.dll\x00GetProcAddress\x00LoadLibraryA\x00",
    b"Hello world. Standard documentation text with https://www.example.com/help link.",
]


def models_dir() -> Path:
    return Path(os.environ.get("SPECIMEN_MODELS", "models"))


@lru_cache(maxsize=1)
def family_model() -> Any | None:
    """The trained behaviour-family model, if ``models/`` has one and the
    optional ML dependencies are installed; otherwise ``None``."""
    p = models_dir()
    if not (p / "family_model.npz").exists():
        return None
    try:
        from .ml.family import FamilyModel
        return FamilyModel.load(p)
    except ImportError:  # pragma: no cover - optional deps missing
        log.info("family model present but numpy/scikit-learn not installed")
        return None


def _benign_traces() -> list[Trace]:
    return [t for t, lab, _ in synthetic_corpus() if lab == 0]


def _replay(trace: Trace) -> tuple[Any, list, Any]:
    graph, timeline = reconstruct(trace)
    # anomaly: rarity of each action vs the benign baseline (reconstruct()
    # drops api_call events without a technique, so align on the same filter)
    evs = [e for e in trace.events if not (e.type == "api_call" and not map_technique(e)[0])]
    for t, ev in zip(timeline, evs):
        t.anomaly = event_anomaly(ev.type, t.technique)
    return graph, timeline, score(trace)


def run(sample_path: str | Path, trace_path: str | Path | None = None,
        benign_blobs: list[bytes] | None = None, force_detonate: bool = False) -> dict[str, Any]:
    """Sample bytes + optional recorded trace (native SPECIMEN or CAPE JSON)."""
    sample, data = load_sample(sample_path)
    static = triage(data)
    trace = graph = behavior = None
    timeline: list = []
    if (static.detonate or force_detonate) and trace_path:
        raw = Path(trace_path).read_bytes()
        doc = json.loads(raw)
        if isinstance(doc, dict) and "behavior" in doc and "events" not in doc:
            trace = cape_to_trace(doc, run_id=Path(trace_path).stem, raw=raw)
        else:
            trace = load_trace(trace_path)
        if trace.sample_sha256 and trace.sample_sha256 != sample.sha256:
            raise ValueError("trace sample_sha256 does not match sample (evidence mismatch)")
        graph, timeline, behavior = _replay(trace)
        if trace.sandbox.startswith("cape"):  # the family model is trained on CAPE reports
            _attach_family(behavior, trace, static_tokens(static_pe(doc)))
    det = synthesize(static, sample.sha256, trace, benign_blobs or DEFAULT_BENIGN_BLOBS, _benign_traces())
    return build_report(sample, static, trace, graph, timeline, behavior, det)


def _attach_family(behavior: Any, trace: Trace, stoks: list[str]) -> None:
    fm = family_model()
    if behavior is None:
        return
    if fm is None:
        # the MVP prototypes are synthetic; do not attribute real reports to them
        behavior.family, behavior.family_similarity = None, 0.0
        behavior.family_model = "none (no trained model in SPECIMEN_MODELS)"
        return
    toks = behavior_tokens(trace) + (stoks if fm.uses_static else [])
    probs = fm.proba([toks])[0]
    i = int(probs.argmax())
    behavior.family = fm.classes[i]
    behavior.family_similarity = round(float(probs[i]), 3)
    behavior.family_model = f"avast-ctu-logreg ({fm.meta.get('variant', 'behaviour+static')})"
    behavior.family_evidence = fm.explain(toks, fm.classes[i], k=6)


def run_report(report_path: str | Path, negatives: list[dict[str, str]] | None = None) -> dict[str, Any]:
    """Report-only analysis of a CAPE/Cuckoo JSON report (no sample bytes).

    Static gate from the report's PE metadata, provenance + timeline from the
    behaviour, family attribution (trained model if available), and
    specificity-checked Sigma (behaviour) + YARA (PE metadata) rules."""
    raw = Path(report_path).read_bytes()
    doc = json.loads(raw)
    trace = cape_to_trace(doc, run_id=Path(report_path).stem, raw=raw)
    pe = static_pe(doc)
    sha = trace.sample_sha256 or sha256_bytes(raw)
    sample = Sample(str(report_path), sha, "", 0)
    static = triage_pe_metadata(pe, sha)
    graph, timeline, behavior = _replay(trace)
    stoks = static_tokens(pe)
    _attach_family(behavior, trace, stoks)
    benign = [blobs([[e.type, e.target or "", e.cmdline or ""] for e in t.events]) for t in _benign_traces()]
    negs = benign + list(negatives or [])
    events = [[e.type, e.target or "", e.cmdline or ""] for e in trace.events]
    sig = synthesize_sigma(events, negs)
    techs = {(e.target or e.cmdline or "").lower(): map_technique(e)[0] for e in trace.events}
    sigma_text = [r.to_sigma(sha, technique=techs.get(r.source.lower())) for r in sig.rules]
    yr = synthesize_yara_pe(stoks, [])
    case = {str(f.get("name", "")).lower(): str(f.get("name", ""))
            for d in pe.get("imports") or [] if isinstance(d, dict)
            for f in d.get("imports") or [] if isinstance(f, dict)}
    yara = yr.to_yara(f"SPECIMEN_{sha[:12]}", sha, case) if yr else None
    det = Detections(yara, sigma_text, [], [f"rejected_nonspecific:{sig.rejected_nonspecific}"])
    rep = build_report(sample, static, trace, graph, timeline, behavior, det)
    rep["manifest"]["execution"] = "report-only (sandbox report replay; no sample bytes handled)"
    rep["manifest"]["report_sha256"] = sha256_bytes(raw)
    return rep
