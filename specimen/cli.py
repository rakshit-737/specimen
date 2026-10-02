"""SPECIMEN CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
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


RELEASE_HINT = ("gh release download v1.0.0 -R rakshit-737/specimen -p 'family_*' -p 'static_*' -D models "
                "(then set SPECIMEN_MODELS=models or run from that directory)")


def _parser() -> argparse.ArgumentParser:
    fmt = argparse.ArgumentDefaultsHelpFormatter
    ap = argparse.ArgumentParser(
        prog="specimen", formatter_class=fmt,
        description="Sample-to-story malware analysis: static gate, sandbox-report / trace replay into a "
                    "provenance graph, family attribution and specificity-checked Sigma + YARA. "
                    "Never executes samples.")
    ap.add_argument("--version", action="version", version=f"specimen {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage", help="static triage only", formatter_class=fmt)
    t.add_argument("sample", help="file to read as bytes (never executed)")
    a = sub.add_parser("analyze", help="full pipeline using a recorded trace", formatter_class=fmt)
    a.add_argument("sample", help="file to read as bytes (never executed)")
    a.add_argument("--trace", help="recorded run: native trace JSON, CAPE/Cuckoo JSON, or Sysmon XML / JSON-lines export")
    a.add_argument("--out", type=Path, help="write report .json/.md here")
    a.add_argument("--force-detonate", action="store_true", help="replay trace even if gate says skip")
    r = sub.add_parser("report", help="report-only analysis of a CAPE/Cuckoo JSON report", formatter_class=fmt)
    r.add_argument("report", help="CAPE/Cuckoo JSON report (full or reduced)")
    r.add_argument("--out", type=Path, help="write report .json/.md here")
    b = sub.add_parser("batch", help="queue a directory of CAPE reports (resumable job ledger)", formatter_class=fmt)
    b.add_argument("directory", type=Path, help="directory containing *.json CAPE/Cuckoo reports")
    b.add_argument("--out", type=Path, default=Path("out/batch"), help="output directory (reports + jobs.jsonl ledger)")
    b.add_argument("--workers", type=int, default=2, help="worker processes")
    e = sub.add_parser("triage-ember", help="static gate (trained LightGBM + TreeSHAP) on EMBER raw-feature JSON lines",
                       formatter_class=fmt)
    e.add_argument("features", type=Path, help="JSON-lines file of EMBER raw features")
    d = sub.add_parser("demo", help="generate inert fixtures and run all demo scenarios", formatter_class=fmt)
    d.add_argument("--out", type=Path, default=Path("out"), help="output directory")
    return ap


def _need_file(ap: argparse.ArgumentParser, path: str | Path | None, what: str) -> None:
    if path is not None and not Path(path).is_file():
        ap.error(f"{what} not found: {path}")


def main(argv: list[str] | None = None) -> int:
    ap = _parser()
    args = ap.parse_args(argv)
    for attr, what in (("sample", "sample"), ("report", "report"), ("trace", "trace"), ("features", "features file")):
        _need_file(ap, getattr(args, attr, None), what)
    try:
        return _dispatch(ap, args)
    except (ValueError, OSError) as e:
        print(f"specimen: error: {e}", file=sys.stderr)
        return 1


def _dispatch(ap: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.cmd == "report":
        rep = run_report(args.report)
        _emit(rep, args.out, Path(args.report).stem)
        bh = rep["behavior"] or {}
        print(json.dumps({"verdict": rep["verdict"], "static_score": rep["static"]["score"],
                          "behaviour_scorer": bh.get("scorer"),
                          "family": bh.get("family"), "family_confidence": bh.get("family_similarity"),
                          "techniques": rep["techniques"], "sigma_rules": len(rep["detections"]["sigma"]),
                          "yara": bool(rep["detections"]["yara"])}, indent=2))
        return 0
    if args.cmd == "batch":
        from .jobqueue import run_batch
        if not args.directory.is_dir():
            ap.error(f"directory not found: {args.directory}")
        files = sorted(args.directory.glob("*.json"))
        if not files:
            ap.error(f"no *.json reports in {args.directory}")
        res = run_batch(files, args.out, args.workers)
        if not res:
            print(f"all {len(files)} jobs already done (ledger: {args.out / 'jobs.jsonl'})")
            return 0
        done = sum(r["status"] == "done" for r in res)
        print(f"{done}/{len(res)} jobs done, ledger: {args.out / 'jobs.jsonl'}")
        return 0 if done == len(res) else 1
    if args.cmd == "triage-ember":
        from .pipeline import models_dir
        md = models_dir()
        missing = [f for f in ("static_lgbm.txt", "static_meta.json") if not (md / f).exists()]
        if missing:
            print(f"specimen: error: EMBER gate model missing in {md}: {', '.join(missing)}. "
                  f"Train it with benchmarks/bench_static.py or fetch the release assets: {RELEASE_HINT}",
                  file=sys.stderr)
            return 1
        from .ml.ember import StaticModel, vectorize
        model = StaticModel.load(md)
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
                          "behaviour_scorer": (rep["behavior"] or {}).get("scorer"),
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
