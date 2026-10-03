"""Research question: do rules auto-synthesized from ONE sandbox run
generalise to sibling samples - without firing on other families or on benign software?

    SPECIMEN_DATA=... python benchmarks/bench_rules.py [--refs 10] [--seeds 5] [--benign PATH]

Protocol (Avast-CTU reduced CAPE reports, temporal split at 2019-08-01):

* for every family with host actions (9 of 10; HarHar reports have none) and
  every seed, draw ``--refs`` reference runs from the *train* split (never one
  of the runs inside the packaged negative corpus) and ``N_NEG`` other-family
  negative runs from the train split;
* synthesize rules from each single run (and from 5 runs pooled);
* measure on the *test* split (later in time):
  - sibling recall   = share of same-family test reports where >= 1 rule fires,
  - cross-family FPR = share of other-family test reports where >= 1 rule fires,
  - novel-behaviour recall = sibling recall on test reports whose behaviour
    token set never occurs in train;
* and on benign software (``--benign``, Quo Vadis Speakeasy clean reports,
  built by ``scripts/build_speakeasy_cache.py`` inside GitHub Actions):
  benign FPR = share of benign reports where >= 1 rule fires.

Negative corpus settings. The product (``specimen report``/``analyze``)
checks rules against the packaged corpus minus the family its trained model
*predicts* (or nothing, without a family model). Several ablation rows
instead remove the *true* family from the negatives; they are labelled
``oracle`` because the product cannot know the true family.

==============================================  ====================  ==========================================
variant                                         candidates            negatives
==============================================  ====================  ==========================================
sigma-mvp                                       technique-gated       synthetic benign (MVP)
sigma-mvp + real neg (oracle)                   technique-gated       synthetic + 1,500 other-family runs
exact + synthetic neg                           every host action,    synthetic benign only
                                                rung 0 only
exact + real neg (oracle)                       rung 0 only           synthetic + 1,500 other-family runs
ladder + synthetic neg                          full ladder           synthetic benign only
ladder + real neg (oracle)                      full ladder           synthetic + 1,500 other-family runs
ladder + real neg, k=3 (oracle)                 full ladder, 3/run    synthetic + 1,500 other-family runs
packaged, true family excluded (oracle)         full ladder           synthetic + packaged corpus - true family
packaged, predicted family excluded (shipped)   full ladder           synthetic + packaged corpus - predicted
                                                                      family (out-of-fold family model)
packaged, no exclusion (default install)        full ladder           synthetic + whole packaged corpus
v2, 5 runs pooled (oracle)                      full ladder           synthetic + 1,500 other-family runs
==============================================  ====================  ==========================================

The predicted family of each reference run comes from 5-fold *cross-fitted*
family models on the train split (behaviour+static tokens, the shipped
variant): the shipped model was fitted on these very runs, so its in-sample
predictions would simply reproduce the oracle.

Uncertainty: per-unit values (family x seed x reference run) go to
``results/rules_avast_units.csv``; CIs are a two-level bootstrap (families,
then units within a family); pooled rates also get Wilson intervals.
Variants are compared with *family-clustered* tests (the 450 units are not
independent): exact Wilcoxon signed-rank and sign-flip permutation tests on
the 9 family-mean differences, plus a two-level bootstrap CI of the
difference. Rule semantics equal Sigma semantics: the emitted Sigma YAML is
checked against pySigma + SQLite in the test suite.

Memory: a slim loader keeps only events/static/family/split per report
(about 3 GB peak with the cross-fitting); run it in the bench workflow.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import itertools
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from common import FIGURES, ROOT, require_data, wilson, write_result
from scipy import stats

from specimen.corpus import synthetic_corpus
from specimen.detect import SigmaRule, blobs, event_line, synthesize_sigma, synthesize_yara_pe
from specimen.models import Event, Trace
from specimen.negatives import FILE as NEG_FILE
from specimen.negatives import import_prevalence, negative_blob
from specimen.synth import sigma_rules

N_NEG = 1500
CACHE = "cache/avast_tokens.jsonl.gz"
BENIGN_CACHE = "cache/speakeasy_benign.jsonl.gz"

ORACLE_V2 = "ladder + real neg (oracle)"
SHIPPED = "packaged, predicted family excluded (shipped)"
DEFAULT = "packaged, no exclusion (default install)"
ORACLE_PKG = "packaged, true family excluded (oracle)"
SIGMA_ORDER = ["sigma-mvp", "sigma-mvp + real neg (oracle)", "exact + synthetic neg", "exact + real neg (oracle)",
               "ladder + synthetic neg", ORACLE_V2, "ladder + real neg, k=3 (oracle)", ORACLE_PKG, SHIPPED, DEFAULT,
               "v2, 5 runs pooled (oracle)"]
YARA_ORDER = ["yara-imphash", "yara-v2 (oracle)", "yara-v2, packaged, predicted family excluded (shipped)",
              "yara-v2, packaged, no exclusion (default install)"]
# short codes keep results/rules_avast_units.csv well under 1 MB
CODES = dict(zip(SIGMA_ORDER + YARA_ORDER, ["mvp", "mvp+real-o", "exact+syn", "exact+real-o", "ladder+syn", "v2-o",
                                             "v2k3-o", "pkg-true-o", "pkg-pred", "pkg-none", "pool5-o", "y-imphash",
                                             "y-v2-o", "y-pkg-pred", "y-pkg-none"]))
NEGATIVES = {
    "sigma-mvp": "synthetic benign", "sigma-mvp + real neg (oracle)": "synthetic + 1,500 other-family runs",
    "exact + synthetic neg": "synthetic benign", "exact + real neg (oracle)": "synthetic + 1,500 other-family runs",
    "ladder + synthetic neg": "synthetic benign", ORACLE_V2: "synthetic + 1,500 other-family runs",
    "ladder + real neg, k=3 (oracle)": "synthetic + 1,500 other-family runs",
    ORACLE_PKG: "packaged corpus minus the true family", SHIPPED: "packaged corpus minus the predicted family",
    DEFAULT: "whole packaged corpus", "v2, 5 runs pooled (oracle)": "synthetic + 1,500 other-family runs",
    "yara-imphash": "none", "yara-v2 (oracle)": "1,500 other-family runs (imphash + import prevalence)",
    "yara-v2, packaged, predicted family excluded (shipped)": "packaged import prevalence minus the predicted family",
    "yara-v2, packaged, no exclusion (default install)": "whole packaged import prevalence",
}
_BENIGN = None


def benign_blobs() -> list[dict[str, str]]:
    """Synthetic benign traces of the MVP corpus as per-category blobs."""
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
    """Train/test records in cache order: events, import tokens, family, behaviour hash, sha256."""
    train, test = [], []
    train_beh: set[str] = set()
    with gzip.open(require_data(CACHE) / CACHE, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            beh = hashlib.sha1(" ".join(sorted(set(r["beh"]))).encode()).hexdigest()
            rec = {"family": r["family"], "events": [tuple(e) for e in r["events"]], "sha256": r["sha256"],
                   "static": frozenset(t for t in r["static"] if t.startswith(("imp:", "imphash:"))), "beh": beh}
            if r["split"] == "train":
                train.append(rec)
                train_beh.add(beh)
            else:
                test.append(rec)
    for r in test:
        r["novel"] = r["beh"] not in train_beh
    return train, test


def packaged_members(train: list[dict]) -> tuple[set[str], bool]:
    """Re-draw the packaged negative corpus's reservoir sample (scripts/build_negative_corpus.py)
    to know which train runs are inside it; verified against the packaged event lines."""
    doc = json.loads(gzip.decompress(NEG_FILE.read_bytes()))
    per, seed = doc["meta"]["per_family"], doc["meta"]["seed"]
    k = max(per.values())
    rng = random.Random(seed)
    res: dict[str, list[dict]] = defaultdict(list)
    seen: dict[str, int] = defaultdict(int)
    for r in train:
        if not r["events"]:
            continue
        fam = r["family"]
        seen[fam] += 1
        if len(res[fam]) < k:
            res[fam].append(r)
        else:
            j = rng.randrange(seen[fam])
            if j < k:
                res[fam][j] = r
    lines: dict[str, set[str]] = defaultdict(set)
    for runs in res.values():
        for r in runs:
            for e in r["events"]:
                x = event_line(e[0], e[1], e[2] if len(e) > 2 else "")
                if x and x[1]:
                    lines[x[0]].add(x[1].replace("\n", " "))
    packaged = {c: {ln for ln, _ in rows} for c, rows in doc["lines"].items()}
    ok = all(lines.get(c, set()) == packaged.get(c, set()) for c in set(lines) | set(packaged))
    return {r["sha256"] for runs in res.values() for r in runs}, ok


def cross_fitted_family(folds: int = 5, seed: int = 0) -> dict[str, str]:
    """Out-of-fold predicted family (argmax, i.e. 'closest' family) for every train run.

    Uses the shipped family-model variant (behaviour+static tokens, hashed LR)
    fitted on the other folds, so no run is scored by a model that saw it."""
    from specimen.ml.family import FamilyModel
    docs, fams, shas = [], [], []
    with gzip.open(require_data(CACHE) / CACHE, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["split"] == "train":
                docs.append(r["beh"] + r["static"])
                fams.append(r["family"])
                shas.append(r["sha256"])
    idx = np.random.default_rng(seed).permutation(len(docs))
    pred: dict[str, str] = {}
    for k in range(folds):
        te = idx[k::folds]
        te_set = set(te.tolist())
        tr = [i for i in range(len(docs)) if i not in te_set]
        m = FamilyModel.fit([docs[i] for i in tr], [fams[i] for i in tr])
        for i, p in zip(te, m.predict([docs[i] for i in te])):
            pred[shas[i]] = p
        acc = np.mean([pred[shas[i]] == fams[i] for i in te])
        print(f"  cross-fit fold {k}: accuracy {acc:.4f}", flush=True)
    return pred


class Evaluator:
    """Per-rule hit vectors over the test split (memoised by category + pattern)."""

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


class BenignEvaluator:
    """Hit vectors over benign Speakeasy reports; a merged blob screens each pattern first."""

    def __init__(self, records: list[dict]) -> None:
        self.blobs = [blobs(r["events"]) for r in records]
        self.merged = merge(self.blobs)
        self.n = len(self.blobs)
        self.with_rule_events = sum(any(b.values()) for b in self.blobs)
        self._memo: dict[tuple, np.ndarray] = {}
        self.pattern_hits: Counter = Counter()
        self.union: dict[str, np.ndarray] = {}

    def record(self, variant: str, hit: np.ndarray) -> None:
        """Track the benign reports hit by *any* run of a variant (for a conservative interval)."""
        if variant in self.union:
            self.union[variant] |= hit
        else:
            self.union[variant] = hit.copy()

    def sigma_hits(self, rules: list[SigmaRule]) -> np.ndarray:
        hit = np.zeros(self.n, dtype=bool)
        for r in rules:
            key = (r.category, r.line_pattern.lower())
            if key not in self._memo:
                if r.matches(self.merged):
                    v = np.fromiter((r.matches(b) for b in self.blobs), bool, self.n)
                else:
                    v = np.zeros(self.n, dtype=bool)
                self._memo[key] = v
                if v.any():
                    self.pattern_hits[key] = int(v.sum())
            hit |= self._memo[key]
        return hit


def load_benign(path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def boot_ci(units: list[dict], key: str, n: int = 2000, seed: int = 0) -> list[float]:
    """Two-level bootstrap (families, then units within family) of the mean."""
    by: dict[str, list[float]] = defaultdict(list)
    for u in units:
        if not np.isnan(u[key]):
            by[u["family"]].append(u[key])
    fams = list(by)
    if not fams:
        return [float("nan"), float("nan")]
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n):
        fs = rng.choice(len(fams), len(fams))
        s = [np.mean(rng.choice(by[fams[i]], len(by[fams[i]]))) for i in fs]
        vals.append(np.mean(s))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return [float(lo), float(hi)]


def clustered_test(units: list[dict], a: str, b: str, key: str, n_boot: int = 4000) -> dict:
    """Family-clustered comparison of variant ``b`` minus ``a`` on ``key``.

    Units are paired on (seed, family, reference run); differences are averaged
    within each family, then tested across the families (exact Wilcoxon
    signed-rank and exact sign-flip permutation), with a two-level bootstrap
    95 % CI of the mean difference (families, then paired units)."""
    ua = {(u["seed"], u["family"], u["ref"]): u[key] for u in units if u["variant"] == a}
    ub = {(u["seed"], u["family"], u["ref"]): u[key] for u in units if u["variant"] == b}
    by: dict[str, list[float]] = defaultdict(list)
    for k in ua:
        if k in ub and not (np.isnan(ua[k]) or np.isnan(ub[k])):
            by[k[1]].append(ub[k] - ua[k])
    fams = sorted(by)
    fm = np.asarray([np.mean(by[f]) for f in fams])
    mean = float(np.mean([d for f in fams for d in by[f]]))
    nz = fm[fm != 0]
    wil = float(stats.wilcoxon(nz, method="exact").pvalue) if len(nz) else 1.0
    obs = abs(fm.mean())
    flips = [abs(np.mean(fm * np.asarray(s))) for s in itertools.product([1, -1], repeat=len(fm))]
    perm = float(np.mean([f >= obs - 1e-15 for f in flips]))
    rng = np.random.default_rng(1)
    boots = []
    for _ in range(n_boot):
        fs = rng.choice(len(fams), len(fams))
        boots.append(np.mean([np.mean(rng.choice(by[fams[i]], len(by[fams[i]]))) for i in fs]))
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return {"a": a, "b": b, "metric": key, "mean_diff": mean, "diff_95ci": [float(lo), float(hi)],
            "families": len(fams), "units": int(sum(len(v) for v in by.values())),
            "family_mean_diffs": {f: float(m) for f, m in zip(fams, fm)},
            "wilcoxon_family_p": wil, "sign_flip_family_p": perm,
            "method": "exact Wilcoxon signed-rank and sign-flip permutation on family-mean differences; "
                      "two-level bootstrap CI"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refs", type=int, default=10)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--benign", default=None, help=f"benign Speakeasy cache (default $SPECIMEN_DATA/{BENIGN_CACHE})")
    ap.add_argument("--folds", type=int, default=5, help="cross-fitting folds for the predicted family")
    a = ap.parse_args()
    root = require_data(CACHE)
    train, test = slim_load()
    ev = Evaluator(test)
    fams = sorted({r["family"] for r in train})
    print(f"{len(train)} train / {len(test)} test, novel test share {ev.novel.mean():.3f}", flush=True)
    members, members_ok = packaged_members(train)
    print(f"packaged negative corpus: {len(members)} member runs re-drawn, lines match: {members_ok}", flush=True)
    if not members_ok:
        members = set()  # cannot identify them; fall back to the unfiltered train pool (recorded)
    pred = cross_fitted_family(a.folds)
    oof_acc = float(np.mean([pred[r["sha256"]] == r["family"] for r in train]))
    print(f"cross-fitted family accuracy on train {oof_acc:.4f}", flush=True)
    bpath = Path(a.benign) if a.benign else root / BENIGN_CACHE
    benign_ev = None
    if bpath.exists():
        brecs = load_benign(bpath)
        benign_ev = BenignEvaluator(brecs)
        print(f"benign Speakeasy reports: {benign_ev.n}", flush=True)
    else:
        print("no benign Speakeasy cache: benign FPR not measured", flush=True)
    syn = benign_blobs()
    pkg_none = negative_blob(None)
    prev_none = import_prevalence(None)
    units: list[dict] = []
    benign_units: list[dict] = []
    pred_right: list[bool] = []
    for seed in range(a.seeds):
        rng = random.Random(seed)
        for fam in fams:
            pool = [r for r in train if r["family"] == fam and r["events"] and r["sha256"] not in members]
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
            refs = rng.sample(pool, min(a.refs, len(pool)))
            for ri, ref in enumerate(refs):
                e = ref["events"]
                own = pred[ref["sha256"]]
                pred_right.append(own == fam)
                pkg_pred = negative_blob(own)
                variants = {
                    "sigma-mvp": mvp_rules(ref, syn),
                    "sigma-mvp + real neg (oracle)": mvp_rules(ref, [*syn, real]),
                    "exact + synthetic neg": synthesize_sigma(e, syn, max_rung=0).rules,
                    "exact + real neg (oracle)": synthesize_sigma(e, [*syn, real], max_rung=0).rules,
                    "ladder + synthetic neg": synthesize_sigma(e, syn).rules,
                    ORACLE_V2: synthesize_sigma(e, [*syn, real]).rules,
                    "ladder + real neg, k=3 (oracle)": synthesize_sigma(e, [*syn, real], max_rules=3).rules,
                    ORACLE_PKG: synthesize_sigma(e, [*syn, negative_blob(fam)]).rules,
                    SHIPPED: synthesize_sigma(e, [*syn, pkg_pred]).rules,
                    DEFAULT: synthesize_sigma(e, [*syn, pkg_none]).rules,
                }
                for name, rules in variants.items():
                    units.append({"seed": seed, "family": fam, "ref": ri, "variant": name, "rules": len(rules),
                                  "predicted_family": own, **ev.score(ev.sigma_hits(rules), fam)})
                    if benign_ev is not None:
                        bh = benign_ev.sigma_hits(rules)
                        benign_ev.record(name, bh)
                        benign_units.append({"seed": seed, "family": fam, "ref": ri, "variant": name,
                                             "benign_fp": int(bh.sum()), "benign_n": benign_ev.n,
                                             "benign_fpr": float(bh.mean())})
                yrules = {
                    "yara-imphash": synthesize_yara_pe(ref["static"], [], with_imphash=True, k=0),
                    "yara-v2 (oracle)": synthesize_yara_pe(ref["static"], neg_static, prev),
                    "yara-v2, packaged, predicted family excluded (shipped)":
                        synthesize_yara_pe(ref["static"], [], import_prevalence(own)),
                    "yara-v2, packaged, no exclusion (default install)":
                        synthesize_yara_pe(ref["static"], [], prev_none),
                }
                for name, rule in yrules.items():
                    units.append({"seed": seed, "family": fam, "ref": ri, "variant": name,
                                  "rules": int(rule is not None), "predicted_family": own,
                                  **ev.score(ev.yara_hits(rule), fam)})
            pooled = []
            for ref in refs[:5]:
                pooled += synthesize_sigma(ref["events"], [*syn, real]).rules
            units.append({"seed": seed, "family": fam, "ref": 0, "variant": "v2, 5 runs pooled (oracle)",
                          "rules": len(pooled) / 5, "predicted_family": "",
                          **ev.score(ev.sigma_hits(pooled), fam)})
            if benign_ev is not None:
                bh = benign_ev.sigma_hits(pooled)
                benign_ev.record("v2, 5 runs pooled (oracle)", bh)
                benign_units.append({"seed": seed, "family": fam, "ref": 0, "variant": "v2, 5 runs pooled (oracle)",
                                     "benign_fp": int(bh.sum()), "benign_n": benign_ev.n, "benign_fpr": float(bh.mean())})
            print(f"seed {seed} {fam:9s}", flush=True)

    summary, per_family = [], []
    for name in SIGMA_ORDER + YARA_ORDER:
        us = [u for u in units if u["variant"] == name]
        fam_means = {f: float(np.nanmean([u["recall"] for u in us if u["family"] == f])) for f in fams
                     if any(u["family"] == f for u in us)}
        fp, ng = sum(u["fp"] for u in us), sum(u["neg"] for u in us)
        row = {
            "synthesizer": name, "negatives": NEGATIVES[name],
            "oracle": "(oracle)" in name,
            "sibling_recall_mean": float(np.nanmean([u["recall"] for u in us])),
            "recall_95ci": boot_ci(us, "recall"),
            "sibling_recall_median_family": float(np.nanmedian(list(fam_means.values()))),
            "novel_behaviour_recall": float(np.nanmean([u["novel_recall"] for u in us])),
            "novel_recall_95ci": boot_ci(us, "novel_recall"),
            "cross_family_fpr_mean": float(np.mean([u["fpr"] for u in us])),
            "fpr_95ci": boot_ci(us, "fpr"),
            "fpr_pooled": fp / ng if ng else float("nan"),
            "fpr_pooled_wilson": list(wilson(fp, ng)),
            "runs_with_any_sibling_hit": float(np.nanmean([u["recall"] > 0 for u in us])),
            "rules_per_run": float(np.mean([u["rules"] for u in us])),
            "units": len(us),
        }
        bus = [u for u in benign_units if u["variant"] == name]
        if bus:
            # every run is checked against the same benign reports, so pooled counts are not independent:
            # the interval is Wilson on the reports hit by ANY run of the variant (an upper bound per run)
            k_any = int(benign_ev.union[name].sum()) if name in benign_ev.union else 0
            row.update({"benign_fpr_mean": float(np.mean([u["benign_fpr"] for u in bus])),
                        "benign_fpr_95ci": boot_ci(bus, "benign_fpr"),
                        "benign_reports_hit_by_any_run": k_any,
                        "benign_any_run_wilson": list(wilson(k_any, benign_ev.n)),
                        "benign_units_with_any_hit": float(np.mean([u["benign_fp"] > 0 for u in bus]))})
        summary.append(row)
        for f, m in fam_means.items():
            fu = [u for u in us if u["family"] == f]
            per_family.append({"variant": name, "family": f, "n_test": int((ev.fam == f).sum()),
                               "recall": m, "fpr": float(np.mean([u["fpr"] for u in fu])),
                               "novel_recall": float(np.nanmean([u["novel_recall"] for u in fu]))
                               if any(not np.isnan(u["novel_recall"]) for u in fu) else None})
    for s in summary:
        print({k: v for k, v in s.items() if k not in ("negatives",)}, flush=True)

    tests = [clustered_test(units, *t) for t in [
        ("sigma-mvp", ORACLE_V2, "recall"),
        ("sigma-mvp", SHIPPED, "recall"),
        ("sigma-mvp", SHIPPED, "fpr"),
        ("sigma-mvp", "exact + synthetic neg", "recall"),
        ("exact + synthetic neg", "ladder + synthetic neg", "recall"),
        ("exact + real neg (oracle)", ORACLE_V2, "recall"),
        ("exact + real neg (oracle)", ORACLE_V2, "fpr"),
        ("ladder + synthetic neg", ORACLE_V2, "recall"),
        ("ladder + synthetic neg", ORACLE_V2, "fpr"),
        ("sigma-mvp", "sigma-mvp + real neg (oracle)", "fpr"),
        (ORACLE_PKG, SHIPPED, "recall"),
        (ORACLE_PKG, SHIPPED, "fpr"),
        (SHIPPED, DEFAULT, "recall"),
        (SHIPPED, DEFAULT, "fpr"),
        (ORACLE_V2, SHIPPED, "recall"),
    ]]
    for t in tests:
        print({k: v for k, v in t.items() if k != "family_mean_diffs"}, flush=True)

    benign_info = None
    if benign_ev is not None:
        meta_p = bpath.with_suffix("").with_suffix(".meta.json")
        benign_info = {"reports": benign_ev.n, "reports_with_rule_relevant_events": benign_ev.with_rule_events,
                       "cache": BENIGN_CACHE,
                       "cache_meta": json.loads(meta_p.read_text()) if meta_p.exists() else None,
                       "top_patterns_hitting_benign": [
                           {"category": c, "pattern": p, "benign_reports_hit": n}
                           for (c, p), n in benign_ev.pattern_hits.most_common(15)],
                       "caveat": "Speakeasy emulates the PE instead of running it, so it records fewer host "
                                 "actions than a CAPE sandbox: benign FPR here is a lower bound for sandbox traces."}

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(8.6, 5.0))
        markers = itertools.cycle("osD^v<>phX*P")
        floor = 1e-6
        for s in summary:
            if s["synthesizer"].startswith("yara"):
                continue
            x0, y = s["cross_family_fpr_mean"], s["sibling_recall_mean"]
            x = max(x0, floor)
            xe = [[x - max(s["fpr_95ci"][0], floor)], [max(s["fpr_95ci"][1], floor) - x]]
            ye = [[y - s["recall_95ci"][0]], [s["recall_95ci"][1] - y]]
            label = s["synthesizer"] + (" (FPR 0, drawn at 1e-6)" if x0 == 0 else "")
            ax.errorbar(x, y, xerr=np.clip(xe, 0, None), yerr=np.clip(ye, 0, None), fmt=next(markers), capsize=3,
                        label=label, mfc="none" if x0 == 0 or s["oracle"] else None, ms=7,
                        lw=2.2 if s["synthesizer"] == SHIPPED else 1.0)
        ax.set_xscale("log")
        ax.set_xlabel("cross-family FPR (log scale; later-in-time test split)")
        ax.set_ylabel("sibling recall (mean, 95 % bootstrap CI)")
        ax.set_title("Sigma from one sandbox run: recall vs false positives (open markers: oracle or FPR 0)")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=7, loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False)
        fig.tight_layout()
        FIGURES.mkdir(parents=True, exist_ok=True)
        fig.savefig(FIGURES / "rule_generalisation.png", dpi=100, bbox_inches="tight")
    except ImportError:
        pass

    write_result("rules_avast", {
        "dataset": "Avast-CTU CAPEv2 reduced reports, temporal split (train < 2019-08-01 <= test)",
        "protocol": {"refs_per_family": a.refs, "seeds": a.seeds, "families": fams,
                     "negatives_for_synthesis": f"{N_NEG} other-family train runs per (seed, family) for the "
                                                f"oracle rows; the packaged corpus (200 train runs per family) "
                                                f"for the packaged rows",
                     "reference_runs": "train runs with host actions, excluding the packaged corpus's own runs",
                     "packaged_members_identified": members_ok, "packaged_members": len(members),
                     "predicted_family": f"{a.folds}-fold cross-fitted FamilyModel (behaviour+static) on train",
                     "cross_fitted_family_accuracy_train": oof_acc,
                     "reference_runs_with_correct_prediction": float(np.mean(pred_right)) if pred_right else None,
                     "novel_test_share": float(ev.novel.mean()),
                     "ci": "two-level bootstrap (families, units); Wilson for pooled rates; family-clustered "
                           "Wilcoxon / sign-flip tests for paired comparisons"},
        "summary": summary, "paired_tests": tests, "per_family": per_family,
        "benign_speakeasy": benign_info,
        "units_file": "results/rules_avast_units.csv",
        "units_variant_codes": CODES,
    })
    cols = ["seed", "family", "ref", "variant", "rules", "predicted_family", "recall", "fpr", "fp", "neg",
            "novel_recall", "benign_fp", "benign_n"]
    bmap = {(u["seed"], u["family"], u["ref"], u["variant"]): u for u in benign_units}
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")  # quotes variant names that contain commas
    w.writerow(cols)
    for u in units:
        b = bmap.get((u["seed"], u["family"], u["ref"], u["variant"]), {})
        row = {**u, "variant": CODES[u["variant"]], "benign_fp": b.get("benign_fp", ""),
               "benign_n": b.get("benign_n", "")}
        w.writerow([f"{row[c]:.6g}" if isinstance(row[c], float) else str(row[c]) for c in cols])
    (ROOT / "results" / "rules_avast_units.csv").write_text(buf.getvalue())
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
