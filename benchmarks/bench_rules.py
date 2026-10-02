"""Research question: do rules auto-synthesized from ONE sandbox run
generalise to sibling samples - without firing on other families?

    SPECIMEN_DATA=... python benchmarks/bench_rules.py [--refs 10] [--seeds 5]

Protocol (Avast-CTU reduced CAPE reports, temporal split at 2019-08-01):

* for every family with host actions (9 of 10; HarHar reports have none) and
  every seed, draw ``--refs`` reference runs and ``N_NEG`` other-family
  negative runs from the *train* split;
* synthesize rules from each single run (and from 5 runs pooled);
* measure on the *test* split (later in time):
  - sibling recall   = share of same-family test reports where >= 1 rule fires,
  - cross-family FPR = share of other-family test reports where >= 1 rule fires,
  - novel-behaviour recall = sibling recall on test reports whose behaviour
    token set never occurs in train (41 % of test reports repeat one).

Synthesizers (the ablation isolates the generalisation ladder from the
negative corpus and from the rule budget):

==========================  =================  ==========================
variant                     candidates          negatives
==========================  =================  ==========================
sigma-mvp                   technique-gated     synthetic benign (MVP)
sigma-mvp + real neg        technique-gated     synthetic + other-family
exact + real neg            ladder rung 0 only  synthetic + other-family
ladder + synthetic neg      full ladder         synthetic benign only
ladder + real neg (v2)      full ladder         synthetic + other-family
ladder + real neg, k=3      full ladder, 3/run  synthetic + other-family
shipped (packaged corpus)   full ladder         synthetic + packaged corpus
                                                (what `specimen report` uses)
v2, 5 runs pooled           full ladder         synthetic + other-family
==========================  =================  ==========================

Uncertainty: per-unit values (family x seed x reference run) are written to
the result file; CIs are a two-level bootstrap (families, then units within a
family); MVP vs v2 is compared with a paired Wilcoxon signed-rank test; tiny
pooled FPRs get Wilson intervals. Rule semantics equal Sigma semantics: the
emitted Sigma YAML is checked against pySigma + SQLite in the test suite.

Memory: a slim loader keeps only events/static/family/split per report
(about 2.5 GB peak); run in the bench workflow or under the heavy lock.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import random
import time
from collections import defaultdict

import numpy as np
from common import FIGURES, md_table, wilson, write_result
from scipy import stats

from specimen.corpus import synthetic_corpus
from specimen.datasets import data_root
from specimen.detect import SigmaRule, blobs, synthesize_sigma, synthesize_yara_pe
from specimen.models import Event, Trace
from specimen.negatives import negative_blob
from specimen.synth import sigma_rules

N_NEG = 1500
_BENIGN = None


def benign_blobs() -> list[dict[str, str]]:
    global _BENIGN
    if _BENIGN is None:
        benign = [t for t, lab, _ in synthetic_corpus() if lab == 0]
        _BENIGN = [blobs([[e.type, e.target or "", e.cmdline or ""] for e in t.events]) for t in benign]
    return _BENIGN


def merge(bl: list[dict[str, str]]) -> dict[str, str]:
    """One blob for many traces (equivalent for a zero-hit specificity check)."""
    out: dict[str, list[str]] = defaultdict(list)
    for b in bl:
        for c, t in b.items():
            if t:
                out[c].append(t)
    return {c: "\n".join(v) for c, v in out.items()}


def mvp_rules(rec: dict, negatives: list[dict[str, str]]) -> list[SigmaRule]:
    """The MVP synthesizer on one record, as wildcard patterns
    (endswith -> '*v', contains -> '*v*'), filtered against ``negatives``."""
    evs = []
    for i, (etype, target, cmd) in enumerate(rec["events"]):
        extra = {"child_pid": 2000 + i} if etype == "process_create" else {}
        evs.append(Event(float(i), etype, 1000, "sample.exe", target=target, cmdline=cmd or None, extra=extra))
    trace = Trace("r", "", "cape-summary", evs)
    out = []
    for cat, _tech, sel, _text in sigma_rules(trace, ""):
        if cat not in ("process_creation", "registry_set", "file_event"):
            continue
        fields = []
        for k, v in sel.items():
            f, op = k.split("|")
            fields.append((f, f"*{v}" if op == "endswith" else f"*{v}*"))
        r = SigmaRule(cat, tuple(fields))
        if not any(r.matches(b) for b in negatives):
            out.append(r)
    return out


def slim_load() -> tuple[list[dict], list[dict]]:
    train, test = [], []
    train_beh: set[str] = set()
    with gzip.open(data_root() / "cache" / "avast_tokens.jsonl.gz", "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            beh = hashlib.sha1(" ".join(sorted(set(r["beh"]))).encode()).hexdigest()
            rec = {"family": r["family"], "events": [tuple(e) for e in r["events"]],
                   "static": frozenset(t for t in r["static"] if t.startswith(("imp:", "imphash:"))), "beh": beh}
            if r["split"] == "train":
                train.append(rec)
                train_beh.add(beh)
            else:
                test.append(rec)
    for r in test:
        r["novel"] = r["beh"] not in train_beh
    return train, test


class Evaluator:
    def __init__(self, test: list[dict]) -> None:
        self.blobs = [blobs(r["events"]) for r in test]
        self.static = [r["static"] for r in test]
        self.fam = np.asarray([r["family"] for r in test])
        self.novel = np.asarray([r["novel"] for r in test])
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

    def score(self, hit: np.ndarray, fam: str) -> dict[str, float]:
        sib = self.fam == fam
        nov = sib & self.novel
        return {"recall": float(hit[sib].mean()) if sib.any() else float("nan"),
                "fpr": float(hit[~sib].mean()), "fp": int(hit[~sib].sum()), "neg": int((~sib).sum()),
                "novel_recall": float(hit[nov].mean()) if nov.any() else float("nan")}


def boot_ci(units: list[dict], key: str, n: int = 2000, seed: int = 0) -> list[float]:
    """Two-level bootstrap (families, then units within family) of the mean."""
    by: dict[str, list[float]] = defaultdict(list)
    for u in units:
        if not np.isnan(u[key]):
            by[u["family"]].append(u[key])
    fams = list(by)
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n):
        fs = rng.choice(len(fams), len(fams))
        s = [np.mean(rng.choice(by[fams[i]], len(by[fams[i]]))) for i in fs]
        vals.append(np.mean(s))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return [round(float(lo), 5), round(float(hi), 5)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refs", type=int, default=10)
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args()
    t0 = time.time()
    train, test = slim_load()
    ev = Evaluator(test)
    fams = sorted({r["family"] for r in train})
    print(f"{len(train)} train / {len(test)} test, novel test share {ev.novel.mean():.3f} ({time.time() - t0:.0f}s)")
    syn = benign_blobs()
    units: list[dict] = []
    for seed in range(a.seeds):
        rng = random.Random(seed)
        for fam in fams:
            pool = [r for r in train if r["family"] == fam and r["events"]]
            if not pool:
                continue
            others = [r for r in train if r["family"] != fam]
            neg = rng.sample(others, min(N_NEG, len(others)))
            real = merge([blobs(r["events"]) for r in neg])
            neg_static = [r["static"] for r in neg]
            prev: dict[str, float] = defaultdict(float)
            for s in neg_static:
                for t in s:
                    if t.startswith("imp:"):
                        prev[t] += 1 / len(neg_static)
            # NB: excludes the true family (oracle); the product excludes its *predicted* family
            packaged = negative_blob(fam)
            refs = rng.sample(pool, min(a.refs, len(pool)))
            for ri, ref in enumerate(refs):
                e = ref["events"]
                variants = {
                    "sigma-mvp": mvp_rules(ref, syn),
                    "sigma-mvp + real neg": mvp_rules(ref, [*syn, real]),
                    "exact + real neg": synthesize_sigma(e, [*syn, real], max_rung=0).rules,
                    "ladder + synthetic neg": synthesize_sigma(e, syn).rules,
                    "ladder + real neg (v2)": synthesize_sigma(e, [*syn, real]).rules,
                    "ladder + real neg, k=3": synthesize_sigma(e, [*syn, real], max_rules=3).rules,
                    "shipped (packaged corpus)": synthesize_sigma(e, [*syn, packaged]).rules,
                }
                for name, rules in variants.items():
                    units.append({"seed": seed, "family": fam, "ref": ri, "variant": name, "rules": len(rules),
                                  **ev.score(ev.sigma_hits(rules), fam)})
                yi = synthesize_yara_pe(ref["static"], [], with_imphash=True, k=0)
                yv2 = synthesize_yara_pe(ref["static"], neg_static, prev)
                for name, rule in (("yara-imphash", yi), ("yara-v2", yv2)):
                    units.append({"seed": seed, "family": fam, "ref": ri, "variant": name, "rules": int(rule is not None),
                                  **ev.score(ev.yara_hits(rule), fam)})
            pooled = []
            for ref in refs[:5]:
                pooled += synthesize_sigma(ref["events"], [*syn, real]).rules
            units.append({"seed": seed, "family": fam, "ref": 0, "variant": "v2, 5 runs pooled",
                          "rules": len(pooled) / 5, **ev.score(ev.sigma_hits(pooled), fam)})
            print(f"seed {seed} {fam:9s} {time.time() - t0:.0f}s", flush=True)

    order = ["sigma-mvp", "sigma-mvp + real neg", "exact + real neg", "ladder + synthetic neg",
             "ladder + real neg (v2)", "ladder + real neg, k=3", "shipped (packaged corpus)", "v2, 5 runs pooled",
             "yara-imphash", "yara-v2"]
    summary, per_family = [], []
    for name in order:
        us = [u for u in units if u["variant"] == name]
        fam_means = {f: float(np.nanmean([u["recall"] for u in us if u["family"] == f])) for f in fams
                     if any(u["family"] == f for u in us)}
        fp, ng = sum(u["fp"] for u in us), sum(u["neg"] for u in us)
        summary.append({
            "synthesizer": name,
            "sibling_recall_mean": round(float(np.nanmean([u["recall"] for u in us])), 4),
            "recall_95ci": boot_ci(us, "recall"),
            "sibling_recall_median_family": round(float(np.median(list(fam_means.values()))), 4),
            "novel_behaviour_recall": round(float(np.nanmean([u["novel_recall"] for u in us])), 4),
            "novel_recall_95ci": boot_ci(us, "novel_recall"),
            "cross_family_fpr_mean": round(float(np.mean([u["fpr"] for u in us])), 6),
            "fpr_95ci": boot_ci(us, "fpr"),
            "fpr_pooled_wilson": list(wilson(fp, ng)),
            "runs_with_any_sibling_hit": round(float(np.nanmean([u["recall"] > 0 for u in us])), 3),
            "rules_per_run": round(float(np.mean([u["rules"] for u in us])), 2),
            "units": len(us),
        })
        for f, m in fam_means.items():
            fu = [u for u in us if u["family"] == f]
            per_family.append({"variant": name, "family": f, "n_test": int((ev.fam == f).sum()),
                               "recall": round(m, 4), "fpr": round(float(np.mean([u["fpr"] for u in fu])), 6),
                               "novel_recall": round(float(np.nanmean([u["novel_recall"] for u in fu])), 4)
                               if any(not np.isnan(u["novel_recall"]) for u in fu) else None})
    for s in summary:
        print(s)

    def paired(x: str, y: str, key: str) -> dict:
        ux = {(u["seed"], u["family"], u["ref"]): u[key] for u in units if u["variant"] == x}
        uy = {(u["seed"], u["family"], u["ref"]): u[key] for u in units if u["variant"] == y}
        ks = [k for k in ux if k in uy and not (np.isnan(ux[k]) or np.isnan(uy[k]))]
        d = np.asarray([uy[k] - ux[k] for k in ks])
        p = float(stats.wilcoxon(d).pvalue) if np.any(d != 0) else 1.0
        return {"a": x, "b": y, "metric": key, "mean_diff": round(float(d.mean()), 5), "n": len(ks), "wilcoxon_p": p}

    tests = [paired("sigma-mvp", "ladder + real neg (v2)", "recall"),
             paired("sigma-mvp + real neg", "ladder + real neg (v2)", "recall"),
             paired("exact + real neg", "ladder + real neg (v2)", "recall"),
             paired("ladder + synthetic neg", "ladder + real neg (v2)", "fpr"),
             paired("sigma-mvp", "sigma-mvp + real neg", "fpr"),
             paired("ladder + real neg (v2)", "shipped (packaged corpus)", "recall")]
    for t in tests:
        print(t)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7.2, 4.4))
        for s in summary:
            if s["synthesizer"].startswith("yara"):
                continue
            x, y = max(s["cross_family_fpr_mean"], 1e-6), s["sibling_recall_mean"]
            xe = [[x - max(s["fpr_95ci"][0], 1e-6)], [max(s["fpr_95ci"][1], 1e-6) - x]]
            ye = [[y - s["recall_95ci"][0]], [s["recall_95ci"][1] - y]]
            ax.errorbar(x, y, xerr=np.clip(xe, 0, None), yerr=np.clip(ye, 0, None), fmt="o", capsize=3)
            ax.annotate(s["synthesizer"], (x, y), textcoords="offset points", xytext=(6, 4), fontsize=8)
        ax.set_xscale("log")
        ax.set_xlabel("cross-family FPR (log scale; later-in-time test split)")
        ax.set_ylabel("sibling recall (mean, 95 % bootstrap CI)")
        ax.set_title("Sigma from one sandbox run: recall vs false positives")
        ax.grid(alpha=0.3, which="both")
        fig.tight_layout()
        FIGURES.mkdir(parents=True, exist_ok=True)
        fig.savefig(FIGURES / "rule_generalisation.png", dpi=110)
    except ImportError:
        pass

    write_result("rules_avast", {
        "dataset": "Avast-CTU CAPEv2 reduced reports, temporal split (train < 2019-08-01 <= test)",
        "protocol": {"refs_per_family": a.refs, "seeds": a.seeds, "families": fams,
                     "negatives_for_synthesis": f"{N_NEG} other-family train runs per (seed, family)",
                     "novel_test_share": round(float(ev.novel.mean()), 4),
                     "ci": "two-level bootstrap (families, units); Wilson for pooled FPR; paired Wilcoxon"},
        "summary": summary, "paired_tests": tests, "per_family": per_family,
        "units_file": "results/rules_avast_units.csv",
        "markdown": md_table(summary, ["synthesizer", "sibling_recall_mean", "recall_95ci",
                                       "sibling_recall_median_family", "novel_behaviour_recall",
                                       "cross_family_fpr_mean", "fpr_95ci", "rules_per_run"]),
    })
    cols = ["seed", "family", "ref", "variant", "rules", "recall", "fpr", "fp", "neg", "novel_recall"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")  # quotes variant names that contain commas
    w.writerow(cols)
    w.writerows([f"{u[c]:.6g}" if isinstance(u[c], float) else str(u[c]) for c in cols] for u in units)
    (FIGURES.parents[1] / "results" / "rules_avast_units.csv").write_text(buf.getvalue())
    print(f"done in {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
