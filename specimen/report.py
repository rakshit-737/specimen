"""Unified confidence-graded report (JSON + Markdown) with run manifest."""
from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .escape import md_text
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
    """Assemble the JSON report: fused verdict, static reasons, timeline, graph, IOCs, rules.

    :returns: a JSON-serialisable dict; the manifest is added by the pipeline.
    """
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


def _fam_score(b: dict[str, Any]) -> str:
    model = str(b.get("family_model") or "")
    if model.startswith("avast"):
        return f"p={b['family_similarity']}, {model}"
    return f"jaccard {b['family_similarity']}"


def _tok(c: Any) -> str:
    if isinstance(c, dict):
        return f"{c.get('feature', c)} (weight {c.get('impact', c.get('weight', ''))})"
    if isinstance(c, (list, tuple)) and len(c) == 2 and isinstance(c[1], (int, float)):
        return f"{c[0]} ({c[1]:+.3f})"
    return str(c)


def _specificity(d: dict[str, Any]) -> str:
    parts = []
    if d["yara_fp_hits"]:
        parts.append(f"YARA rule hit {len(d['yara_fp_hits'])} benign blob(s)")
    for x in d["sigma_fp_hits"]:
        k, _, v = str(x).partition(":")
        if k == "rejected_nonspecific":
            parts.append(f"{v} Sigma candidate(s) dropped because no generalisation rung was specific enough")
        else:
            parts.append(f"Sigma candidate {md_text(k)} dropped (hit benign trace {md_text(v)})")
    return "; ".join(parts) + "."


def render_markdown(rep: dict[str, Any]) -> str:
    """Human-readable Markdown report; every report-derived string is escaped and IOCs are defanged."""
    v = rep["verdict"]
    L = [f"# SPECIMEN report - `{str(rep['sample']['sha256'])[:16]}`", "",
         f"**Verdict:** {v['label']} (score {v['score']}, confidence {v['confidence']})  ",
         f"**Detonated:** {'yes (recorded trace replay)' if rep['detonated'] else 'no - static gate triaged out'}", "",
         "## Static triage", f"score {rep['static']['score']} / entropy {rep['static']['entropy']}", ""]
    L += [f"- {md_text(r['feature'])} impact {r['impact']:+.2f}" for r in rep["static"]["top_reasons"]] or ["- no suspicious static features"]
    if rep["behavior"]:
        b = rep["behavior"]
        L += ["", "## Behavior", f"P(malicious)={b['probability']} label={b['label']} scorer={b.get('scorer', '')}"
              + (f" | family match **{md_text(b['family'])}** ({_fam_score(b)})" if b["family"] else ""), ""]
        L += [f"- {md_text(c['feature'])} = {c['value']}, impact {c['impact']:+.2f}" for c in b["contributions"][:6]]
        if b.get("family_evidence"):
            L += ["", "### Family evidence", f"Top tokens supporting **{md_text(b['family'])}** ({md_text(b.get('family_model', ''))}):", ""]
            L += [f"- {md_text(_tok(c))}" for c in b["family_evidence"]]
    if rep["timeline"]:
        L += ["", "## Timeline", "| t | event | ATT&CK | anomaly |", "|---|---|---|---|"]
        L += [f"| {t['ts']:.2f} | {md_text(t['description'])} | {t['technique'] or ''} {t['tactic'] or ''} | {t['anomaly']} |"
              for t in rep["timeline"]]
    if rep["graph"]:
        L += ["", "## Provenance graph", "```mermaid", rep["graph"]["mermaid"], "```"]
    L += ["", "## IOCs (defanged)"] + [f"- **{k}**: {', '.join(md_text(x) for x in vals)}"
                                        for k, vals in rep["iocs"].items() if vals]
    d = rep["detections"]
    if d["yara"]:
        L += ["", "## YARA", "```yara", d["yara"], "```"]
    for i, s in enumerate(d["sigma"], 1):
        cat = next((ln.split(":", 1)[1].strip() for ln in s.splitlines() if ln.strip().startswith("category:")), "")
        L += ["", f"## Sigma {i} - {cat}", "```yaml", s, "```"]
    if d["yara_fp_hits"] or d["sigma_fp_hits"]:
        L += ["", "Specificity: " + _specificity(d)]
    L += ["", "## Evidence manifest", "```json", json.dumps(rep["manifest"], indent=2), "```", ""]
    return "\n".join(L)
