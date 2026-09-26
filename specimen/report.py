"""Unified confidence-graded report (JSON + Markdown) with run manifest."""
from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .hashing import sha256_bytes
from .models import BehaviorScore, Detections, Sample, StaticVerdict, TimelineEntry, Trace, to_dict
from .provenance import ProvenanceGraph


def fuse(static: StaticVerdict, behavior: BehaviorScore | None) -> tuple[str, str, float]:
    s = static.score
    if behavior is None:
        return static.label, "medium" if static.label == "benign" else "low", s
    b = behavior.probability
    final = max(s, b)
    label = "malicious" if final >= 0.8 else "suspicious" if final >= 0.5 else "benign"
    agree = (s >= 0.5) == (b >= 0.5)
    conf = "high" if agree and abs(s - b) < 0.5 else "medium" if agree else "low-static/behavior-disagree"
    if not agree and b >= 0.8:
        conf = "medium (behavior-driven)"
    return label, conf, round(final, 4)


def build_report(sample: Sample, static: StaticVerdict, trace: Trace | None,
                 graph: ProvenanceGraph | None, timeline: list[TimelineEntry],
                 behavior: BehaviorScore | None, det: Detections) -> dict[str, Any]:
    label, conf, final = fuse(static, behavior)
    iocs = dict(static.iocs)
    if trace:
        iocs["network"] = sorted({e.target for e in trace.events if e.type == "net_connect" and e.target})
        iocs["domains"] = sorted({e.target for e in trace.events if e.type == "dns_query" and e.target})
        iocs["dropped_files"] = sorted({e.target for e in trace.events
                                        if e.type == "file_write" and e.target and e.target.lower().endswith((".exe", ".dll", ".ps1"))})
        iocs["registry"] = sorted({e.target for e in trace.events if e.type == "registry_set" and e.target})
    rep: dict[str, Any] = {
        "tool": "SPECIMEN", "version": __version__,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sample": to_dict(sample),
        "verdict": {"label": label, "score": final, "confidence": conf},
        "static": {"score": static.score, "label": static.label, "detonate": static.detonate,
                   "entropy": static.entropy, "is_pe": static.is_pe,
                   "top_reasons": to_dict(static.reasons[:8])},
        "behavior": to_dict(behavior) if behavior else None,
        "detonated": trace is not None,
        "techniques": sorted({t.technique for t in timeline if t.technique}),
        "timeline": to_dict(timeline),
        "graph": {"nodes": len(graph.nodes), "edges": len(graph.edges),
                  "mermaid": graph.to_mermaid()} if graph else None,
        "iocs": iocs,
        "detections": to_dict(det),
    }
    rep["manifest"] = {
        "sample_sha256": sample.sha256,
        "trace_sha256": trace.source_sha256 if trace else None,
        "trace_run_id": trace.run_id if trace else None,
        "python": platform.python_version(),
        "specimen_version": __version__,
        "execution": "trace-replay (no live detonation)",
    }
    body = json.dumps({k: v for k, v in rep.items() if k != "generated_utc"}, sort_keys=True, default=str)
    rep["manifest"]["report_content_sha256"] = sha256_bytes(body.encode())
    return rep


def render_markdown(rep: dict[str, Any]) -> str:
    v = rep["verdict"]
    L = [f"# SPECIMEN report - `{rep['sample']['sha256'][:16]}`", "",
         f"**Verdict:** {v['label']} (score {v['score']}, confidence {v['confidence']})  ",
         f"**Detonated:** {'yes (recorded trace replay)' if rep['detonated'] else 'no - static gate triaged out'}", "",
         "## Static triage", f"score {rep['static']['score']} / entropy {rep['static']['entropy']}", ""]
    L += [f"- `{r['feature']}` impact {r['impact']:+.2f}" for r in rep["static"]["top_reasons"]] or ["- no suspicious static features"]
    if rep["behavior"]:
        b = rep["behavior"]
        L += ["", "## Behavior", f"P(malicious)={b['probability']} label={b['label']} scorer={b.get('scorer', '')}"
              + (f" | family match **{b['family']}** (jaccard {b['family_similarity']})" if b["family"] else "")]
        L += [f"- `{c['feature']}`={c['value']} impact {c['impact']:+.2f}" for c in b["contributions"][:6]]
    if rep["timeline"]:
        L += ["", "## Timeline", "| t | event | ATT&CK | anomaly |", "|---|---|---|---|"]
        L += [f"| {t['ts']:.2f} | {t['description'].replace('|', '/')} | {t['technique'] or ''} {t['tactic'] or ''} | {t['anomaly']} |"
              for t in rep["timeline"]]
    if rep["graph"]:
        L += ["", "## Provenance graph", "```mermaid", rep["graph"]["mermaid"], "```"]
    L += ["", "## IOCs"] + [f"- **{k}**: {', '.join(vals)}" for k, vals in rep["iocs"].items() if vals]
    d = rep["detections"]
    if d["yara"]:
        L += ["", "## YARA", "```yara", d["yara"], "```"]
    for s in d["sigma"]:
        L += ["", "## Sigma", "```yaml", s, "```"]
    if d["yara_fp_hits"] or d["sigma_fp_hits"]:
        L += ["", f"Specificity: YARA FP {d['yara_fp_hits']}; dropped Sigma {d['sigma_fp_hits']}"]
    L += ["", "## Evidence manifest", "```json", json.dumps(rep["manifest"], indent=2), "```", ""]
    return "\n".join(L)
