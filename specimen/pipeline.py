"""Orchestration: triage -> (trace replay) -> reconstruct -> score -> synthesize -> report."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .corpus import synthetic_corpus
from .provenance import reconstruct
from .report import build_report
from .scoring import event_anomaly, score
from .static_triage import load_sample, triage
from .synth import synthesize
from .trace import load_trace

DEFAULT_BENIGN_BLOBS = [
    b"MZ\x90\x00This program cannot be run in DOS mode.\x00kernel32.dll\x00GetProcAddress\x00LoadLibraryA\x00",
    b"Hello world. Standard documentation text with https://www.example.com/help link.",
]


def run(sample_path: str | Path, trace_path: str | Path | None = None,
        benign_blobs: list[bytes] | None = None, force_detonate: bool = False) -> dict[str, Any]:
    sample, data = load_sample(sample_path)
    static = triage(data)
    trace = graph = behavior = None
    timeline = []
    if (static.detonate or force_detonate) and trace_path:
        trace = load_trace(trace_path)
        if trace.sample_sha256 and trace.sample_sha256 != sample.sha256:
            raise ValueError("trace sample_sha256 does not match sample (evidence mismatch)")
        graph, timeline = reconstruct(trace)
        for t, ev in zip(timeline, trace.events):
            t.anomaly = event_anomaly(ev.type, t.technique)
        behavior = score(trace)
    benign_traces = [t for t, lab, _ in synthetic_corpus() if lab == 0]
    det = synthesize(static, sample.sha256, trace, benign_blobs or DEFAULT_BENIGN_BLOBS, benign_traces)
    return build_report(sample, static, trace, graph, timeline, behavior, det)
