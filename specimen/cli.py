"""SPECIMEN CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .lab_fixtures import write_fixtures
from .pipeline import run
from .report import render_markdown
from .static_triage import load_sample, triage
from .models import to_dict


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
    a.add_argument("--trace", help="recorded/synthetic behavior trace JSON")
    a.add_argument("--out", type=Path, help="write report .json/.md here")
    a.add_argument("--force-detonate", action="store_true", help="replay trace even if gate says skip")
    d = sub.add_parser("demo", help="generate inert fixtures and run all demo scenarios")
    d.add_argument("--out", type=Path, default=Path("out"))
    args = ap.parse_args(argv)

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
