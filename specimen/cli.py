"""SPECIMEN CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .lab_fixtures import write_fixtures
from .models import to_dict
from .pipeline import run, run_report
from .report import render_markdown
from .static_triage import load_sample, triage


def _emit(rep: dict, out: Path | None, stem: str) -> None:
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{stem}.json").write_text(json.dumps(rep, indent=2, default=str))
        (out / f"{stem}.md").write_text(render_markdown(rep), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="specimen", description="Sample-to-story pipeline (trace-replay MVP; never executes samples)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage", help="static triage only")
    t.add_argument("sample")
    a = sub.add_parser("analyze", help="full pipeline using a recorded trace")
    a.add_argument("sample")
    a.add_argument("--trace", help="recorded run: native trace JSON, CAPE/Cuckoo JSON, or Sysmon XML / JSON-lines export")
    a.add_argument("--out", type=Path, help="write report .json/.md here")
    a.add_argument("--force-detonate", action="store_true", help="replay trace even if gate says skip")
    r = sub.add_parser("report", help="report-only analysis of a CAPE/Cuckoo JSON report")
    r.add_argument("report")
    r.add_argument("--out", type=Path, help="write report .json/.md here")
    b = sub.add_parser("batch", help="queue a directory of CAPE reports (resumable job ledger)")
    b.add_argument("directory", type=Path)
    b.add_argument("--out", type=Path, default=Path("out/batch"))
    b.add_argument("--workers", type=int, default=2)
    e = sub.add_parser("triage-ember", help="static gate (trained LightGBM + TreeSHAP) on EMBER raw-feature JSON lines")
    e.add_argument("features", type=Path, help="JSON-lines file of EMBER raw features")
    d = sub.add_parser("demo", help="generate inert fixtures and run all demo scenarios")
    d.add_argument("--out", type=Path, default=Path("out"))
    args = ap.parse_args(argv)

    if args.cmd == "report":
        rep = run_report(args.report)
        _emit(rep, args.out, Path(args.report).stem)
        bh = rep["behavior"] or {}
        print(json.dumps({"verdict": rep["verdict"], "static_score": rep["static"]["score"],
                          "family": bh.get("family"), "family_confidence": bh.get("family_similarity"),
                          "techniques": rep["techniques"], "sigma_rules": len(rep["detections"]["sigma"]),
                          "yara": bool(rep["detections"]["yara"])}, indent=2))
        return 0
    if args.cmd == "batch":
        from .jobqueue import run_batch
        res = run_batch(args.directory.glob("*.json"), args.out, args.workers)
        done = sum(r["status"] == "done" for r in res)
        print(f"{done}/{len(res)} jobs done, ledger: {args.out / 'jobs.jsonl'}")
        return 0 if done == len(res) else 1
    if args.cmd == "triage-ember":
        from .ml.ember import StaticModel, vectorize
        from .pipeline import models_dir
        model = StaticModel.load(models_dir())
        for line in args.features.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            x = vectorize(row)
            p = float(model.predict(x.reshape(1, -1))[0])
            print(json.dumps({"sha256": row.get("sha256"), "score": round(p, 4),
                              "detonate": p >= model.threshold, "threshold": round(model.threshold, 5),
                              "top_shap": model.explain(x, 6)}))
        return 0

    if args.cmd == "triage":
        _, data = load_sample(args.sample)
        v = triage(data)
        print(json.dumps({k: val for k, val in to_dict(v).items() if k != "strings"}, indent=2))
        return 0
    if args.cmd == "analyze":
        rep = run(args.sample, args.trace, force_detonate=args.force_detonate)
        _emit(rep, args.out, Path(args.sample).stem)
        print(json.dumps({"verdict": rep["verdict"], "detonated": rep["detonated"],
                          "techniques": rep["techniques"],
                          "family": (rep["behavior"] or {}).get("family")}, indent=2))
        return 0
    fx = write_fixtures(args.out / "fixtures")
    print(f"{'sample':<20} {'gate':<8} {'verdict':<11} {'conf':<28} {'family':<20} sigma yara")
    for name, (sp, tp) in fx.items():
        rep = run(sp, tp)
        _emit(rep, args.out / "reports", sp.stem)
        b = rep["behavior"] or {}
        print(f"{name:<20} {'detonate' if rep['detonated'] else 'skip':<8} {rep['verdict']['label']:<11} "
              f"{rep['verdict']['confidence']:<28} {str(b.get('family')):<20} "
              f"{len(rep['detections']['sigma']):>5} {'yes' if rep['detections']['yara'] else 'no'}")
    print(f"\nReports written to {args.out / 'reports'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
