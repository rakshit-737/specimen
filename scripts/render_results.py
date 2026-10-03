"""Render the result tables in README.md and docs/*.md from results/*.json.

    python scripts/render_results.py          # rewrite the generated blocks
    python scripts/render_results.py --check  # exit 1 if any block is out of date (CI)

Every number in a generated block comes from a committed result file and is
rounded once, here. Blocks are delimited by ``<!-- gen:NAME -->`` and
``<!-- /gen:NAME -->``; each table ends with its source file, bench run id and
commit.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"
TARGETS = [ROOT / "README.md", ROOT / "docs" / "benchmarks.md", ROOT / "docs" / "index.md",
           ROOT / "docs" / "how-it-works.md", ROOT / "docs" / "reproduce.md", ROOT / "THREAT_MODEL.md"]
RUN_URL = "https://github.com/rakshit-737/specimen/actions/runs/"


def load(name: str) -> dict[str, Any]:
    return json.loads((RES / f"{name}.json").read_text(), parse_constant=lambda c: float("nan"))


# ---------------------------------------------------------------- formatting

def p3(x: float | None) -> str:
    return "-" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.3f}"


def pct(x: float | None, d: int = 1) -> str:
    return "-" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{100 * x:.{d}f} %"


def ci3(c: list[float] | None) -> str:
    return "" if not c else f"[{c[0]:.3f}, {c[1]:.3f}]"


def cipct(c: list[float] | None, d: int = 1) -> str:
    return "" if not c else f"[{100 * c[0]:.{d}f}, {100 * c[1]:.{d}f}]"


def pval(p: float | None) -> str:
    if p is None or (isinstance(p, float) and math.isnan(p)):
        return "-"
    return f"{p:.2g}" if p >= 1e-3 else f"{p:.1e}"


def nb(d: dict | None, scale: float = 1.0, digits: int = 3) -> str:
    """mean [lo, hi] from an interval dict ({mean, ci95})."""
    if not d:
        return "-"
    m, (lo, hi) = d["mean"], d["ci95"]
    if scale == 100:
        return f"{100 * m:.{digits}f} [{100 * lo:.{digits}f}, {100 * hi:.{digits}f}] %"
    return f"{m:.{digits}f} [{lo:.{digits}f}, {hi:.{digits}f}]"


def source(*names: str) -> str:
    parts = []
    for n in names:
        pv = load(n).get("provenance") or {}
        rid, sha = pv.get("github_run_id"), (pv.get("commit") or "")[:7]
        where = f"bench run [{rid}]({RUN_URL}{rid})" if rid else "local run"
        parts.append(f"`results/{n}.json` ({where}, commit `{sha}`)" if sha else f"`results/{n}.json` ({where})")
    return "Source: " + "; ".join(parts) + "."


def table(head: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


# ---------------------------------------------------------------- blocks

SHIPPED = "packaged, predicted family excluded (shipped)"
LABELS = {
    "sigma-mvp": "Sigma MVP (technique-gated exact values, synthetic negatives)",
    "sigma-mvp + real neg (oracle)": "Sigma MVP + real negatives (oracle)",
    "exact + synthetic neg": "every host action, exact values, synthetic negatives",
    "exact + real neg (oracle)": "every host action, exact values + real negatives (oracle)",
    "ladder + synthetic neg": "ladder + synthetic negatives only",
    "ladder + real neg (oracle)": "ladder + 1,500 other-family negatives (true family excluded, oracle)",
    "ladder + real neg, k=3 (oracle)": "same, at most 3 rules (oracle)",
    "packaged, true family excluded (oracle)": "packaged corpus, true family excluded (oracle)",
    SHIPPED: "**packaged corpus, predicted family excluded (shipped)**",
    "packaged, no exclusion (default install)": "packaged corpus, no exclusion (default install, no family model)",
    "v2, 5 runs pooled (oracle)": "ladder + other-family negatives, 5 runs pooled (oracle)",
    "yara-imphash": "YARA `pe.imphash()`",
    "yara-v2 (oracle)": "YARA v2, other-family negatives (oracle)",
    "yara-v2, packaged, predicted family excluded (shipped)": "YARA v2, packaged prevalence, predicted family excluded (shipped)",
    "yara-v2, packaged, no exclusion (default install)": "YARA v2, packaged prevalence, no exclusion (default install)",
}


def rules_row(name: str) -> dict:
    return next(s for s in load("rules_avast")["summary"] if s["synthesizer"] == name)


def rules_test(a: str, b: str, metric: str) -> dict:
    return next(t for t in load("rules_avast")["paired_tests"] if t["a"] == a and t["b"] == b and t["metric"] == metric)


def block_rules() -> str:
    d = load("rules_avast")
    rows = []
    for s in d["summary"]:
        b = s.get("benign_fpr_mean")
        rows.append([LABELS.get(s["synthesizer"], s["synthesizer"]),
                     f"{p3(s['sibling_recall_mean'])} {ci3(s['recall_95ci'])}",
                     p3(s["sibling_recall_median_family"]),
                     f"{p3(s['novel_behaviour_recall'])} {ci3(s['novel_recall_95ci'])}",
                     f"{pct(s['cross_family_fpr_mean'], 3)} {cipct(s['fpr_95ci'], 3)}",
                     "-" if b is None else f"{pct(b, 3)} {cipct(s.get('benign_any_run_wilson'), 3)}",
                     f"{s['rules_per_run']:.1f}"])
    t = table(["synthesizer (ablation)", "sibling recall [95 % CI]", "median family", "novel-behaviour recall",
               "cross-family FPR [95 % CI]", "benign FPR (Speakeasy) [Wilson 95 %]", "rules / run"], rows)
    bs = d.get("benign_speakeasy") or {}
    et = ((bs.get("cache_meta") or {}).get("event_types") or {})
    note = (f"\n\nBenign FPR: share of the {bs['reports']:,} benign Quo Vadis Speakeasy reports on which any rule "
            f"of a run fires (mean over runs); the interval is Wilson on the reports hit by *any* run of the row, an "
            f"upper bound for a single run (all runs share the same benign reports, so their counts cannot be "
            f"pooled). Only {bs.get('reports_with_rule_relevant_events', 0):,} of these reports contain an event a "
            f"Sigma rule here can match ({et.get('file_write', 0):,} file writes, {et.get('process_create', 0):,} "
            f"process creations, {et.get('registry_set', 0):,} registry value writes in total): the emulator records "
            f"far fewer host actions than a sandbox, so this is a weak lower bound, not a benign-FPR estimate for "
            f"sandbox traces."
            if bs.get("reports") else "\n\nBenign FPR: not measured in this run (no Speakeasy cache).")
    pr = d["protocol"]
    note += (f" Predicted family: {pr['predicted_family']}; it matches the true family for "
             f"{pct(pr.get('reference_runs_with_correct_prediction'))} of the reference runs.")
    return t + note + "\n\n" + source("rules_avast")


def block_rules_tests() -> str:
    d = load("rules_avast")
    rows = []
    for t in d["paired_tests"]:
        unit = "FPR" if t["metric"] == "fpr" else "recall"
        diff = (f"{100 * t['mean_diff']:+.3f} pp [{100 * t['diff_95ci'][0]:+.3f}, {100 * t['diff_95ci'][1]:+.3f}]"
                if unit == "FPR" else
                f"{t['mean_diff']:+.3f} [{t['diff_95ci'][0]:+.3f}, {t['diff_95ci'][1]:+.3f}]")
        rows.append([LABELS.get(t["a"], t["a"]).replace("**", ""), LABELS.get(t["b"], t["b"]).replace("**", ""),
                     unit, diff, pval(t["wilcoxon_family_p"]), pval(t["sign_flip_family_p"])])
    return (table(["a", "b", "metric", "b - a [95 % CI]", "Wilcoxon p (9 families)", "sign-flip p"], rows)
            + "\n\nTests are on the family-mean differences (the 450 units are clustered within 9 families; "
              "with 9 families the smallest attainable two-sided p is 0.0039). " + source("rules_avast"))


def block_rules_findings() -> str:
    d = load("rules_avast")
    sh = rules_row(SHIPPED)
    dflt = rules_row("packaged, no exclusion (default install)")
    orc = rules_row("packaged, true family excluded (oracle)")
    ladder = rules_test("exact + real neg (oracle)", "ladder + real neg (oracle)", "recall")
    cand = rules_test("sigma-mvp", "exact + synthetic neg", "recall")
    negf = rules_test("ladder + synthetic neg", "ladder + real neg (oracle)", "fpr")
    mvpr = rules_test("sigma-mvp", SHIPPED, "recall")
    mvpf = rules_test("sigma-mvp", SHIPPED, "fpr")
    pf = {r["family"]: r["recall"] for r in d["per_family"] if r["variant"] == SHIPPED}
    fam = ", ".join(f"{f} {p3(v)}" for f, v in sorted(pf.items(), key=lambda kv: -(kv[1] if kv[1] == kv[1] else -1)))
    sig = "significant" if mvpr["wilcoxon_family_p"] < 0.05 else "not significant"
    return "\n".join([
        f"- **Shipped configuration:** recall {p3(sh['sibling_recall_mean'])} {ci3(sh['recall_95ci'])} "
        f"(median family {p3(sh['sibling_recall_median_family'])}) at {pct(sh['cross_family_fpr_mean'], 3)} "
        f"{cipct(sh['fpr_95ci'], 3)} cross-family FPR; the oracle true-family exclusion gives "
        f"{p3(orc['sibling_recall_mean'])} at {pct(orc['cross_family_fpr_mean'], 3)}.",
        f"- **Without a family model** (pip/Docker default) nothing is excluded, so rules that also match the "
        f"sample's own family in the packaged corpus are dropped: recall {p3(dflt['sibling_recall_mean'])} "
        f"{ci3(dflt['recall_95ci'])}.",
        f"- **False positives come down because of the real negative corpus:** with synthetic negatives only, "
        f"the ladder reaches {pct(rules_row('ladder + synthetic neg')['cross_family_fpr_mean'], 2)} FPR; real "
        f"negatives change FPR by {100 * negf['mean_diff']:+.2f} pp (family-level Wilcoxon p = "
        f"{pval(negf['wilcoxon_family_p'])}).",
        f"- **Recall comes from candidate generation, not the ladder or the negatives:** using every host action "
        f"instead of technique-gated events adds {cand['mean_diff']:+.3f} recall {ci3(cand['diff_95ci'])} "
        f"(p = {pval(cand['wilcoxon_family_p'])}); the generalisation ladder adds only "
        f"{ladder['mean_diff']:+.3f} {ci3(ladder['diff_95ci'])} over exact values (p = "
        f"{pval(ladder['wilcoxon_family_p'])}).",
        f"- **Against the MVP**, the shipped synthesizer changes recall by {mvpr['mean_diff']:+.3f} "
        f"{ci3(mvpr['diff_95ci'])} ({sig} at family level, p = {pval(mvpr['wilcoxon_family_p'])}) and FPR by "
        f"{100 * mvpf['mean_diff']:+.2f} pp (p = {pval(mvpf['wilcoxon_family_p'])}).",
        f"- **The mean hides the spread** (shipped, per family): {fam}. Emotet, Trickbot and Ursnif randomise "
        f"every artefact that reduced reports record.",
    ]) + "\n\n" + source("rules_avast")


def block_family() -> str:
    d = load("family_avast")
    names = {"mvp-jaccard": "MVP Jaccard over ATT&CK technique sets", "static-only": "static.pe tokens only",
             "behaviour-only": "behaviour tokens only", "behaviour+static": "behaviour + static tokens"}
    shipped = d["selection"]["shipped"]
    va = d["selection"]["validation_accuracy"]
    rows = []
    for m in d["metrics"]:
        if m["model"] in names:
            label = names[m["model"]]
            if m["model"] == shipped:
                label = f"**{label} (shipped; best on validation, {va[shipped]:.3f})**"
            elif m["model"] in va:
                label += f" (validation {va[m['model']]:.3f})"
            rows.append([label, f"{p3(m['accuracy'])} {ci3(m['accuracy_95ci'])}",
                         f"{p3(m['novel_behaviour_accuracy'])} {ci3(m.get('novel_95ci'))}", p3(m["macro_f1"])])
        else:
            rows.append([f"*{m['model']}*", f"*{m['accuracy']}*", "", ""])
    mc = d["mcnemar"]
    return (table(["model", "test accuracy [Wilson 95 %]", "novel-behaviour accuracy", "macro-F1"], rows)
            + f"\n\nMcNemar, behaviour-only vs behaviour+static on test: {mc['a_right_b_wrong']} vs "
              f"{mc['a_wrong_b_right']} discordant reports, p = {pval(mc['p_value'])}. "
            + source("family_avast"))


def block_family_openset() -> str:
    o = load("family_avast")["open_set"]
    t = o["test_at_tau"]
    v = next(c for c in o["validation_curve"] if c["tau"] == o["abstain_below"])
    rows = [["validation (2019-06..07; chosen here)", f"{o['abstain_below']:.2f}", pct(v["known_coverage"]),
             pct(v["known_accuracy_covered"]), pct(v["unseen_family_accepted"])],
            ["test (applied unchanged)", f"{o['abstain_below']:.2f}",
             f"{pct(t['known_coverage'])} {cipct(t['known_coverage_95ci'])}",
             f"{pct(t['known_accuracy_covered'])} {cipct(t['known_accuracy_covered_95ci'])}",
             f"{pct(t['unseen_family_accepted'])} {cipct(t['unseen_family_accepted_95ci'])}"]]
    meds = [x["median_max_p"] for x in o["test_lofo"].values()]
    return (table(["split", "abstain below", "known-family coverage", "accuracy on covered", "unseen family accepted"],
                  rows)
            + f"\n\nLeave-one-family-out on test: the median top probability of a held-out family's reports is "
              f"{min(meds):.2f}-{max(meds):.2f}. Below the threshold reports say `unknown (closest: X)`. "
            + source("family_avast"))


def block_static_temporal() -> str:
    d = load("static_ember_temporal")
    t, r, u = d["summary"]
    b0 = t.get("seed0_test_row_bootstrap_95ci", {})
    h = d["baselines_same_test_rows"][0]

    def tcell(k: str, pctv: bool = False) -> str:
        x = t[k]
        if pctv:
            d = 2 if k == "malware_missed" else 1
            return f"{100 * x['mean']:.{d}f} % [{100 * x['ci95'][0]:.{d}f}, {100 * x['ci95'][1]:.{d}f}]"
        return f"{x['mean']:.4f} [{x['ci95'][0]:.4f}, {x['ci95'][1]:.4f}]" if k == "roc_auc" else \
            f"{x['mean']:.3f} [{x['ci95'][0]:.3f}, {x['ci95'][1]:.3f}]"
    rows = [["**temporal, SPECIMEN gate** (5 seeds)", tcell("roc_auc"), tcell("tpr@0.1%fpr"), tcell("tpr@1%fpr"),
             tcell("detonations_saved", True), tcell("malware_missed", True), tcell("benign_skipped", True)],
            ["same, seed 0, bootstrap over test rows",
             "" if not b0.get("roc_auc") else f"[{b0['roc_auc'][0]:.4f}, {b0['roc_auc'][1]:.4f}]",
             ci3(b0.get("tpr@0.1%fpr")), ci3(b0.get("tpr@1%fpr")), "", "", ""],
            ["MVP heuristic gate, same test rows", f"{h['roc_auc']:.3f} {ci3(h.get('roc_auc_95ci'))}",
             p3(h["tpr@0.1%fpr"]), p3(h["tpr@1%fpr"]), pct(h["detonations_saved"]), pct(h["malware_missed"], 2),
             pct(h["benign_skipped"])],
            ["detonate every PE (what `analyze` does)", "-", "-", "-", "0 %", "0 %", "0 %"],
            ["random split, same months and volume",
             f"{r['roc_auc']['mean']:.4f} [{r['roc_auc']['ci95'][0]:.4f}, {r['roc_auc']['ci95'][1]:.4f}]",
             f"{r['tpr@0.1%fpr']['mean']:.3f} {ci3(r['tpr@0.1%fpr']['ci95'])}",
             f"{r['tpr@1%fpr']['mean']:.3f} {ci3(r['tpr@1%fpr']['ci95'])}", "", "", ""],
            ["*upstream EMBER-2018 LightGBM (600k Jan-Oct rows, EMBER features)*", f"*{u['roc_auc']:.5f}*",
             f"*{u['tpr@0.1%fpr']:.3f}*", f"*{u['tpr@1%fpr']:.3f}*", "", "", ""]]
    return (table(["protocol", "ROC AUC", "TPR @ 0.1 % FPR", "TPR @ 1 % FPR", "detonations saved",
                   "malware missed", "benign skipped"], rows)
            + "\n\nIntervals for the 5 seeds are 95 % t-intervals over seeds (seed variance only: the test rows are "
              "fixed); the seed-0 row bootstraps the test rows. " + source("static_ember_temporal"))


def block_static_random() -> str:
    d = load("static_ember")
    names = {"mvp-heuristic": "MVP heuristic (ported)", "logreg": "logistic regression",
             "lightgbm": "LightGBM (SPECIMEN)"}
    rows = [[names.get(m["model"], m["model"]), f"{m['roc_auc']:.3f} {ci3(m.get('roc_auc_95ci'))}",
             f"{m['tpr@0.1%fpr']:.3f} {ci3(m.get('tpr@0.1%fpr_95ci'))}", p3(m["tpr@1%fpr"]), p3(m["accuracy"]),
             p3(m["f1"])] for m in d["metrics"]]
    return (table(["model", "ROC AUC [bootstrap 95 %]", "TPR @ 0.1 % FPR", "TPR @ 1 % FPR", "accuracy", "F1"], rows)
            + "\n\n" + source("static_ember"))


def block_behaviour() -> str:
    d = load("behaviour_malbehavd")
    names = {"mvp-synthetic": "MVP scorer (synthetic-trained, ATT&CK features)",
             "attack-features": "same 9 ATT&CK features, retrained",
             "api-ngram-lr": "**API uni+bigram tokens + LR (shipped scorer)**",
             "api-ngram-lgbm": "API uni+bigram tokens + LightGBM"}
    hold = {r["model"]: r for r in d["holdout"]}
    seeds = {r["model"]: r for r in d["seeds_70_30"]}
    cv = {r["model"]: r for r in d["cv"]}
    dd = {r["model"]: r for r in d["dedup_70_30"]}
    rows = []
    for k, label in names.items():
        h = hold[k]
        rows.append([label, f"{h['accuracy']:.3f} {ci3(h['accuracy_95ci'])}", nb(seeds[k]["accuracy"]),
                     nb(cv[k]["cv_accuracy"]), nb(dd[k]["accuracy"]) if k in dd else ""])
    for p in d["published"]:
        rows.append([f"*{p['model']}* ({p.get('source', '')})", f"*{p['accuracy']}*", "", "", ""])
    leak = d["duplicate_leakage"]
    pp = d["pipeline_path"]
    return (table(["model", "seed-0 holdout [bootstrap 95 %]", "5 x 70/30 (paper protocol)", "5x5-fold CV",
                   "5 x 70/30, duplicate-free"], rows)
            + f"\n\n- Duplicates: {leak['distinct_sequences']:,} distinct sequences in {leak['rows']:,} rows; "
              f"{nb(leak['test_rows_with_exact_duplicate_in_train'], 100, 1)} of test rows have an exact copy in "
              f"train. The LR is {nb(leak['lr_accuracy_on_seen_rows'], 100, 1)} accurate on those and "
              f"{nb(leak['lr_accuracy_on_unseen_rows'], 100, 1)} on unseen rows."
              f"\n- Simulated shipped routing (per-split LR for traces with at least {pp['min_calls']} calls, "
              f"MVP scorer otherwise; p >= 0.5 counts as not benign): accuracy {nb(pp['accuracy'])}; at the "
              f"report's 'malicious' cut-off (p >= 0.8) {nb(pp['malicious_recall_at_0.8'], 100, 1)} of malicious "
              f"traces are labelled malicious. {pct(pp['share_under_20_calls'])} of traces have fewer than 20 calls."
              f"\n- Intervals: Nadeau-Bengio corrected t over repeated splits/folds (logit scale near 0/1). "
            + source("behaviour_malbehavd"))


def block_maldetconv() -> str:
    d = load("repro_maldetconv")
    archs = list(d["architectures"])
    rows = []
    paper = {r["n"]: r for r in d["rows"] if r["protocol"].startswith("paper")}
    dedup = {r["n"]: r for r in d["rows"] if r["protocol"].startswith("dedup")}
    for n in sorted(paper):
        a, b = paper[n], dedup.get(n)
        t = a["lr_minus_reproduction"]
        rows.append([str(n), f"{a['paper_table3']:.3f}", nb(a["reproduction"][archs[0]]),
                     nb(a["reproduction"][archs[1]]), nb(a["specimen_lr"]),
                     f"{t['mean_diff']:+.3f}, p = {pval(t['p'])}",
                     nb(b["reproduction"][archs[0]]) if b else "", nb(b["specimen_lr"]) if b else ""])
    return (table(["n calls", f"paper ({d['paper_sources']['table3']})", "reproduction, Fig. 10 architecture",
                   "reproduction, round-3 guess (ablation)", "SPECIMEN LR", "LR - reproduction (corrected paired t)",
                   "reproduction, duplicate-free inputs", "SPECIMEN LR, duplicate-free inputs"], rows)
            + f"\n\n{d['seeds']} seeds x random 70/30; {d['epochs']} epochs (not stated in the paper). "
            + source("repro_maldetconv"))


def block_li2024() -> str:
    d = load("api_cross")["repro_li2024"]
    prot = list(d["protocols"])
    rows_by = {p: {(r["model"], r["features"]): r for r in d["protocols"][p]["rows"]} for p in prot}
    label = {"random-forest": "Random Forest", "xgboost": "XGBoost", "knn": "KNN", "nn-4-layer": "NN, 4 hidden layers",
             "specimen-lr": "SPECIMEN LR"}
    feats = {"tfidf": "TF-IDF", "tfidf+pca": "TF-IDF + PCA (SVD 100)", "uni+bigram": "uni+bigram TF-IDF"}
    rows = []
    for key, r in rows_by[prot[0]].items():
        other = rows_by[prot[1]].get(key)
        name = f"{label[key[0]]}, {feats[key[1]]}"
        if key[0] == "specimen-lr":
            name = f"**{name}**"
        rows.append([name, "-" if r["paper_table1"] is None else f"{r['paper_table1']:.2f}", nb(r["accuracy"]),
                     nb(other["accuracy"]) if other else ""])
    tests = []
    for t in d["protocols"][prot[0]]["paired_tests"]:
        tests.append([t["a"], t["b"], f"{t['mean_diff']:+.3f} [{t['ci95'][0]:+.3f}, {t['ci95'][1]:+.3f}]",
                      pval(t["p"])])
    return (table(["model, features", "paper (Table I, p. 6)", "reproduction, all rows (5 seeds x 5-fold)",
                   "reproduction, duplicate-free"], rows)
            + "\n\nFeature-matched comparisons on identical folds (all rows; Nadeau-Bengio corrected paired t):\n\n"
            + table(["a", "b", "b - a [95 % CI]", "p"], tests)
            + "\n\nNo grid search was run: the paper grid-searches (section 5.1, p. 6) but does not give the "
              "ranges, so defaults are used; part of any gap to the paper may come from that. "
            + source("api_cross"))


def block_cross() -> str:
    d = load("api_cross")
    rows = [[r["input"], f"{r['threshold']:.1f}", f"{pct(r['detection_rate'])} {cipct(r['wilson_95ci'])}"]
            for r in d["cross_dataset_malbehavd_to_malapi"]["rows"]]
    o = d["oliveira_within_dataset"]
    return (table(["Mal-API-2019 input", "threshold", "flagged [Wilson 95 %]"], rows)
            + f"\n\nWithin Oliveira (integer-coded calls, duplicate-free, 5-fold x seeds, class-balanced LR): "
              f"balanced accuracy {nb(o['balanced_accuracy'])}, ROC AUC {nb(o['roc_auc'])}. "
            + source("api_cross"))


def block_headline() -> str:
    st = load("static_ember_temporal")["summary"][0]
    fam = load("family_avast")
    shipped = fam["selection"]["shipped"]
    fm = next(m for m in fam["metrics"] if m["model"] == shipped)
    jac = next(m for m in fam["metrics"] if m["model"] == "mvp-jaccard")
    sh, mvp = rules_row(SHIPPED), rules_row("sigma-mvp")
    beh = load("behaviour_malbehavd")
    lr = next(r for r in beh["seeds_70_30"] if r["model"] == "api-ngram-lr")
    lrd = next(r for r in beh["dedup_70_30"] if r["model"] == "api-ngram-lr")
    mvpb = next(r for r in beh["seeds_70_30"] if r["model"] == "mvp-synthetic")
    h = load("static_ember_temporal")["baselines_same_test_rows"][0]
    benign = sh.get("benign_fpr_mean")
    rows = [
        ["Can a static gate skip detonations safely? [^gate]", "EMBER 2018, temporal (train Jan-Sep, test Nov-Dec)",
         f"skips {pct(st['benign_skipped']['mean'], 0)} of benign, misses {pct(st['malware_missed']['mean'], 1)} of "
         f"malware; AUC {st['roc_auc']['mean']:.3f} [{st['roc_auc']['ci95'][0]:.3f}, {st['roc_auc']['ci95'][1]:.3f}]",
         f"heuristic AUC {h['roc_auc']:.2f}; detonate all: 0 % saved",
         "EMBER LightGBM, 600k rows: AUC 0.996 [^ember]"],
        ["Which family is it?", "Avast-CTU CAPEv2, temporal split",
         f"{pct(fm['accuracy'])} {cipct(fm['accuracy_95ci'])} [^fam]", f"Jaccard: {pct(jac['accuracy'])}",
         "HMIL: 94.5 %"],
        ["Do Sigma rules from **one** run catch later siblings?", "Avast-CTU, 9 families x 10 runs x 5 seeds",
         f"recall {p3(sh['sibling_recall_mean'])} {ci3(sh['recall_95ci'])} at {pct(sh['cross_family_fpr_mean'], 3)} "
         f"cross-family FPR" + (f", {pct(benign, 3)} benign FPR" if benign is not None else "") + " [^rules]",
         f"MVP: {p3(mvp['sibling_recall_mean'])} at {pct(mvp['cross_family_fpr_mean'], 2)}", "none found"],
        ["Is the behaviour malicious?", "MalbehavD-V1, 2,570 Cuckoo API traces",
         f"{nb(lrd['accuracy'], 100, 1)} duplicate-free; {nb(lr['accuracy'], 100, 1)} on the paper's random splits "
         f"[^beh]", f"MVP scorer: {pct(mvpb['accuracy']['mean'], 0)}",
         "MalDetConv 96.1 % (random split)"],
    ]
    notes = [
        "[^gate]: Standalone `triage-ember` model on EMBER raw features; `analyze` has no PE-to-EMBER extractor and "
        "still detonates every PE. Threshold for 99 % recall calibrated on October; 5 subsample seeds, 95 % "
        "t-intervals (seed variance only).",
        "[^ember]: Upstream benchmark trains on all 600k Jan-Oct rows with EMBER's own features; SPECIMEN uses a "
        "132k-row Jan-Sep subsample and holds October out, so the gap is not drift alone.",
        f"[^fam]: Shipped {shipped} model, chosen on a temporal validation slice; Wilson 95 % interval.",
        "[^rules]: Shipped configuration: packaged negative corpus minus the family the trained model predicts. "
        "Mean over 450 runs with a two-level bootstrap CI; the median family is much lower (see Evaluation). Benign "
        "FPR is on emulator (Speakeasy) reports, a lower bound.",
        "[^beh]: Shipped API n-gram LR; Nadeau-Bengio corrected 95 % intervals. 42 % of random-split test rows have an "
        "exact duplicate in train, which inflates the paper-protocol number.",
    ]
    return (table(["Question", "Data", "SPECIMEN [95 % CI]", "Baseline", "Published"], rows) + "\n\n"
            + "\n".join(notes) + "\n\nAll cells come from `results/*.json`, produced by the `bench` workflow; each "
              "table on the [Evaluation](https://rakshit-737.github.io/specimen/benchmarks/) page names its run id.")


def demo(name: str = "avast_njrat_1") -> dict:
    return json.loads((ROOT / "docs" / "demo" / "summary.json").read_text())["inputs"][name]


def block_demo_example() -> str:
    s = demo()
    lok = demo("avast_lokibot_1")
    keys = [("verdict", s["verdict"]), ("static_score", s["static_score"]),
            ("behaviour_scorer", s["behaviour_scorer"]), ("family", s["family"]),
            ("family_confidence", s["family_p"]), ("techniques", s["techniques"]),
            ("sigma_rules", s["sigma_rules"]), ("yara", s["yara"])]
    body = ",\n ".join(f"{json.dumps(k)}: {json.dumps(v)}" for k, v in keys)
    return ("```json\n{" + body + "}\n```\n\n"
            f"With the same model the trimmed Lokibot fixture comes out as `{lok['family']}` "
            f"(p = {lok['family_p']}) with {lok['sigma_rules']} Sigma rules. Generated from "
            "`docs/demo/summary.json` (`scripts/build_demo.py`).")


def block_walk_static() -> str:
    s = demo()
    top = s["static_top"][0] if s["static_top"] else {"feature": "-", "impact": 0}
    return f"The PE-metadata heuristic scores it {s['static_score']} (top reason `{top['feature']}` {top['impact']:+.2f})."


def block_walk_behaviour() -> str:
    s = demo()
    tops = ", ".join(f"`{c['feature']}` ({c['impact']:+.2f})" for c in s["behaviour_top"])
    return (f"Here the scorer is `{s['behaviour_scorer']}`, P(malicious) = {s['behaviour_p']}, driven by {tops}. "
            f"Fused with the static score the verdict is **{s['verdict']['label']}** ({s['verdict']['score']}, "
            f"confidence {s['verdict']['confidence']}).")


def block_walk_family() -> str:
    s = demo()
    ev = ", ".join(f"`{t} ({w:+.3f})`" for t, w in s["family_evidence"])
    return (f"Result for this run: **{s['family']}, p = {s['family_p']}** ({s['family_model']}). The tokens that "
            f"drove it: {ev}.")


def block_walk_graph() -> str:
    return "```mermaid\n" + demo()["graph"]["mermaid"] + "\n```"


def block_walk_timeline() -> str:
    rows = [[f"{t['ts']:.2f}", t["description"].replace("|", "/"), f"{t['technique']} {t['tactic']}"]
            for t in demo()["timeline_head"]]
    return table(["t", "event", "ATT&CK"], rows)


def block_walk_sigma() -> str:
    s = demo()
    rule = s["first_sigma"] or ""
    det = rule.split("detection:", 1)[1].split("level:", 1)[0].rstrip() if "detection:" in rule else ""
    rung = next((ln.split("rung", 1)[1].split(";", 1)[0].strip() for ln in rule.splitlines()
                 if "generalisation rung" in ln), "?")
    return (f"This run yields {s['sigma_rules']} Sigma rules; the first (generalisation rung {rung}):\n\n"
            "```yaml\ndetection:" + det + "\n```")


REPRO = [
    ("static_ember_temporal", "static-temporal", "python benchmarks/bench_static_temporal.py --seeds 5",
     lambda d: f"AUC {d['summary'][0]['roc_auc']['mean']:.4f}, TPR@0.1% {d['summary'][0]['tpr@0.1%fpr']['mean']:.3f}"),
    ("static_ember", "static", "python benchmarks/bench_static.py",
     lambda d: f"LightGBM AUC {next(m for m in d['metrics'] if m['model'] == 'lightgbm')['roc_auc']:.4f}"),
    ("rules_avast", "rules", "python benchmarks/bench_rules.py --seeds 5 --benign <speakeasy cache>",
     lambda d: "shipped recall {:.3f}, FPR {:.4f} %".format(
         next(x for x in d["summary"] if x["synthesizer"] == SHIPPED)["sibling_recall_mean"],
         100 * next(x for x in d["summary"] if x["synthesizer"] == SHIPPED)["cross_family_fpr_mean"])),
    ("family_avast", "family", "python benchmarks/bench_family.py",
     lambda d: "shipped {} accuracy {:.4f}, tau {}".format(
         d["selection"]["shipped"], next(m for m in d["metrics"] if m["model"] == d["selection"]["shipped"])["accuracy"],
         d["open_set"]["abstain_below"])),
    ("behaviour_malbehavd", "malbehavd", "python benchmarks/bench_malbehavd.py",
     lambda d: "LR 70/30 {:.4f}, duplicate-free {:.4f}".format(
         next(r for r in d["seeds_70_30"] if r["model"] == "api-ngram-lr")["accuracy"]["mean"],
         next(r for r in d["dedup_70_30"] if r["model"] == "api-ngram-lr")["accuracy"]["mean"])),
    ("api_cross", "api-cross", "python benchmarks/bench_api_cross.py --seeds 5",
     lambda d: "Li et al. RF (TF-IDF) {:.4f}".format(next(
         r for r in next(iter(d["repro_li2024"]["protocols"].values()))["rows"]
         if r["model"] == "random-forest" and r["features"] == "tfidf")["accuracy"]["mean"])),
    ("repro_maldetconv", "maldetconv", "python benchmarks/repro_maldetconv.py --seeds 10 --epochs 20",
     lambda d: "n=100 reproduction {:.4f}".format(next(
         r for r in d["rows"] if r["n"] == 100 and r["protocol"].startswith("paper"))["reproduction"][
         next(iter(d["architectures"]))]["mean"])),
]


def block_reproduce() -> str:
    rows = []
    for name, suite, cmd, head in REPRO:
        d = load(name)
        pv = d.get("provenance") or {}
        rid = pv.get("github_run_id")
        mins = pv.get("runtime_s")
        rows.append([f"`{name}.json`", f"`suite={suite}`", f"`{cmd}`",
                     f"{mins / 60:.0f} min" if isinstance(mins, (int, float)) else "-",
                     f"[{rid}]({RUN_URL}{rid})" if rid else "local", f"`{(pv.get('commit') or '')[:7]}`", head(d)])
    return (table(["result file", "bench suite", "script", "wall clock (Actions)", "source run", "commit",
                   "expected headline value"], rows)
            + "\n\nWall clock is the script's own runtime on a GitHub-hosted ubuntu-24.04 runner (4 vCPU), "
              "excluding downloads. Re-runs on other hardware should agree within the published intervals.")


def block_threat_fpr() -> str:
    sh = rules_row(SHIPPED)
    v2 = rules_row("ladder + real neg (oracle)")
    orc = rules_row("packaged, true family excluded (oracle)")
    b = sh.get("benign_fpr_mean")
    benign = (f" and fire on {pct(b, 3)} {cipct(sh.get('benign_any_run_wilson'), 3)} of benign Speakeasy reports "
              f"(an emulator lower bound: these reports contain few host actions)" if b is not None else "")
    return (f"**Measured rule false positives** (`results/rules_avast.json`): with the shipped negative corpus "
            f"(packaged corpus minus the predicted family) rules from one run fire on "
            f"{pct(sh['cross_family_fpr_mean'], 3)} {cipct(sh['fpr_95ci'], 3)} of later other-family sandbox "
            f"reports{benign}. The oracle settings, which remove the true family from the negatives and are not "
            f"what the product does, give {pct(v2['cross_family_fpr_mean'], 3)} {cipct(v2['fpr_95ci'], 3)} "
            f"(1,500 other-family runs) and {pct(orc['cross_family_fpr_mean'], 3)} {cipct(orc['fpr_95ci'], 3)} "
            f"(packaged corpus). " + source("rules_avast"))


BLOCKS = {"headline": block_headline, "threat-fpr": block_threat_fpr, "demo-example": block_demo_example, "reproduce": block_reproduce, "walk-static": block_walk_static,
          "walk-behaviour": block_walk_behaviour, "walk-family": block_walk_family, "walk-graph": block_walk_graph,
          "walk-timeline": block_walk_timeline, "walk-sigma": block_walk_sigma, "rules": block_rules, "rules-tests": block_rules_tests,
          "rules-findings": block_rules_findings, "family": block_family, "family-openset": block_family_openset,
          "static-temporal": block_static_temporal, "static-random": block_static_random,
          "behaviour": block_behaviour, "maldetconv": block_maldetconv, "li2024": block_li2024, "cross": block_cross}
_BLOCK = re.compile(r"(<!-- gen:([a-z0-9-]+) -->\n)(.*?)(\n<!-- /gen:\2 -->)", re.S)


def render(text: str) -> str:
    cache: dict[str, str] = {}

    def sub(m: re.Match[str]) -> str:
        name = m.group(2)
        if name not in BLOCKS:
            raise SystemExit(f"unknown generated block {name!r}")
        if name not in cache:
            cache[name] = BLOCKS[name]()
        return m.group(1) + cache[name] + m.group(4)
    return _BLOCK.sub(sub, text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    stale = []
    for p in TARGETS:
        old = p.read_text(encoding="utf-8")
        new = render(old)
        if new != old:
            stale.append(p.relative_to(ROOT).as_posix())
            if not a.check:
                p.write_text(new, encoding="utf-8", newline="\n")
    if a.check and stale:
        print("generated tables are out of date in: " + ", ".join(stale) + " (run python scripts/render_results.py)")
        return 1
    print(("updated: " + ", ".join(stale)) if stale else "all generated tables up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
