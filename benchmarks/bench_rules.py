"""Research question: do rules auto-synthesized from ONE sandbox run
generalise to sibling samples - without firing on other families?

    SPECIMEN_DATA=... python benchmarks/bench_rules.py [--refs 10]

Protocol (Avast-CTU reduced CAPE reports, temporal split):

* for every family, draw ``--refs`` reference runs from the *train* split;
* synthesize rules from each single run (and from 5 runs pooled);
* measure on the *test* split (later in time):
  - sibling recall   = share of same-family test samples where >= 1 rule fires,
  - cross-family FPR = share of other-family test samples where >= 1 rule fires.

Sigma synthesizers compared:
  ``mvp``  - the original technique-gated exact-value synthesizer (synth.py),
             specificity-checked against its synthetic benign traces;
  ``v2``   - specificity-constrained generalisation (detect.py), negatives =
             1,500 other-family *train* runs.
YARA (static.pe) compared:
  ``imphash``   - classic imphash-equality rule;
  ``v2``        - imphash OR >= 75 % of the 8 rarest imports, dropped on any
                  negative hit.
"""
from __future__ import annotations

import argparse
import random
import time
from collections import defaultdict

import numpy as np
from common import FIGURES, md_table, write_result

from specimen.corpus import synthetic_corpus
from specimen.detect import SigmaRule, blobs, synthesize_sigma, synthesize_yara_pe
from specimen.ml.avast import load_cache
from specimen.models import Event, Trace
from specimen.synth import sigma_rules

N_NEG = 1500


def mvp_rules(rec: dict) -> list[SigmaRule]:
    """Run the MVP synthesizer on one record and express its selections as
    wildcard patterns (identical semantics: endswith -> '*v', contains -> '*v*')."""
    evs = []
    for i, (etype, target, cmd) in enumerate(rec["events"]):
        extra = {"child_pid": 2000 + i} if etype == "process_create" else {}
        evs.append(Event(float(i), etype, 1000, "sample.exe", target=target, cmdline=cmd or None, extra=extra))
    trace = Trace(rec["sha256"], rec["sha256"], "cape-summary", evs)
    benign = [t for t, lab, _ in synthetic_corpus() if lab == 0]
    benign_blobs = [blobs([[e.type, e.target or "", e.cmdline or ""] for e in t.events]) for t in benign]
    out = []
    cat_map = {"process_creation": "process_creation", "registry_set": "registry_set", "file_event": "file_event"}
    for cat, _tech, sel, _text in sigma_rules(trace, rec["sha256"]):
        if cat not in cat_map:
            continue
        fields = []
        for k, v in sel.items():
            f, op = k.split("|")
            fields.append((f, f"*{v}" if op == "endswith" else f"*{v}*"))
        r = SigmaRule(cat, tuple(fields))
        if not any(r.matches(b) for b in benign_blobs):
            out.append(r)
    return out


class Evaluator:
    def __init__(self, test: list[dict]) -> None:
        self.blobs = [blobs(r["events"]) for r in test]
        self.static = [set(r["static"]) for r in test]
        self.fam = np.asarray([r["family"] for r in test])
        self._memo: dict[tuple, np.ndarray] = {}

    def sigma_hits(self, rules: list[SigmaRule]) -> np.ndarray:
        hit = np.zeros(len(self.blobs), dtype=bool)
        for r in rules:
            key = (r.category, r.line_pattern.lower())
            if key not in self._memo:
                self._memo[key] = np.fromiter((r.matches(b) for b in self.blobs), bool, len(self.blobs))
            hit |= self._memo[key]
        return hit

    def yara_hits(self, rule) -> np.ndarray:
        if rule is None:
            return np.zeros(len(self.static), dtype=bool)
        return np.fromiter((rule.matches(s) for s in self.static), bool, len(self.static))

    def score(self, hit: np.ndarray, fam: str) -> tuple[float, float]:
        sib = self.fam == fam
        return float(hit[sib].mean()) if sib.any() else float("nan"), float(hit[~sib].mean())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refs", type=int, default=10)
    a = ap.parse_args()
    rng = random.Random(0)
    recs = list(load_cache())
    train = [r for r in recs if r["split"] == "train"]
    test = [r for r in recs if r["split"] == "test"]
    fams = sorted({r["family"] for r in recs})
    ev = Evaluator(test)
    print(f"{len(train)} train / {len(test)} test")

    agg: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    per_family = []
    t0 = time.time()
    for fam in fams:
        pool = [r for r in train if r["family"] == fam and r["events"]]
        if not pool:
            continue
        others = [r for r in train if r["family"] != fam]
        neg = rng.sample(others, min(N_NEG, len(others)))
        neg_blobs = [blobs(r["events"]) for r in neg]
        neg_static = [set(r["static"]) for r in others]
        prev: dict[str, float] = defaultdict(float)
        for s in neg_static:
            for t in s:
                if t.startswith("imp:"):
                    prev[t] += 1 / len(neg_static)
        refs = rng.sample(pool, min(a.refs, len(pool)))
        res = defaultdict(list)
        for ref in refs:
            v2 = synthesize_sigma(ref["events"], neg_blobs)
            mvp = mvp_rules(ref)
            for name, rules in (("sigma-mvp", mvp), ("sigma-v2", v2.rules)):
                rec, fpr = ev.score(ev.sigma_hits(rules), fam)
                res[name].append((rec, fpr, len(rules)))
            yi = synthesize_yara_pe(ref["static"], [], with_imphash=True, k=0)
            yv2 = synthesize_yara_pe(ref["static"], neg_static, prev)
            for name, rule in (("yara-imphash", yi), ("yara-v2", yv2)):
                rec, fpr = ev.score(ev.yara_hits(rule), fam)
                res[name].append((rec, fpr, int(rule is not None)))
        # 5 runs pooled
        pooled = []
        for ref in refs[:5]:
            pooled += synthesize_sigma(ref["events"], neg_blobs).rules
        rec, fpr = ev.score(ev.sigma_hits(pooled), fam)
        res["sigma-v2 (5 runs pooled)"].append((rec, fpr, len(pooled)))
        row = {"family": fam, "n_test": int((ev.fam == fam).sum())}
        for name, vals in res.items():
            arr = np.asarray(vals, dtype=float)
            row[name] = f"{np.nanmean(arr[:, 0]):.3f} / {np.mean(arr[:, 1]):.4f}"
            for v in vals:
                agg[name]["recall"].append(v[0])
                agg[name]["fpr"].append(v[1])
                agg[name]["n"].append(v[2])
        per_family.append(row)
        print(f"{fam:10s} {time.time() - t0:.0f}s  " + "  ".join(f"{k}={v}" for k, v in row.items()
                                                                 if k not in ("family",)), flush=True)

    summary = []
    for name, d in agg.items():
        rec = np.asarray(d["recall"], dtype=float)
        summary.append({"synthesizer": name,
                        "sibling_recall_mean": round(float(np.nanmean(rec)), 4),
                        "cross_family_fpr_mean": round(float(np.mean(d["fpr"])), 5),
                        "runs_with_any_hit_on_siblings": round(float(np.nanmean(rec > 0)), 3),
                        "rules_per_run": round(float(np.mean(d["n"])), 2)})
    for s in summary:
        print(s)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        names = [s["synthesizer"] for s in summary]
        x = np.arange(len(names))
        fig, ax = plt.subplots(figsize=(7, 3.6))
        ax.bar(x - 0.2, [s["sibling_recall_mean"] for s in summary], 0.4, label="sibling recall")
        ax.bar(x + 0.2, [s["cross_family_fpr_mean"] for s in summary], 0.4, label="cross-family FPR")
        ax.set_xticks(x, names, rotation=20, ha="right")
        ax.set_ylim(0, 1)
        ax.set_title("Rules from one sandbox run: generalisation vs specificity")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        FIGURES.mkdir(parents=True, exist_ok=True)
        fig.savefig(FIGURES / "rule_generalisation.png", dpi=110)
    except ImportError:
        pass

    cols = ["family", "n_test"] + list(agg)
    write_result("rules_avast", {
        "dataset": "Avast-CTU CAPEv2 reduced reports, temporal split",
        "protocol": {"refs_per_family": a.refs, "negatives_for_synthesis": f"{N_NEG} other-family train runs",
                     "cell_format": "sibling recall / cross-family FPR"},
        "summary": summary, "per_family": per_family,
        "markdown": md_table(summary, ["synthesizer", "sibling_recall_mean", "cross_family_fpr_mean",
                                       "runs_with_any_hit_on_siblings", "rules_per_run"])
        + "\n\n" + md_table(per_family, cols),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
