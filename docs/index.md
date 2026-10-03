# SPECIMEN

**Contribution, in one sentence:** SPECIMEN measures, on a temporal split of 48,976 CAPEv2 reports and on 32,673 benign emulation reports, how often Sigma rules synthesised from *one* sandbox run and checked against a real negative corpus catch later siblings without firing on other families or on benign software, inside one explainable sample-to-report pipeline; the ablation separates what candidate generation, the generalisation ladder and the negative corpus each contribute.

[![njRAT demo report](figures/demo.png)](demo/avast_njrat_1.md)

**One sample (or one sandbox report) in, one defensible story out:** what the sample is, what it did on the host, how to detect it next time, and the evidence behind each conclusion.

!!! warning "Lab-only, never executes anything"
    SPECIMEN reads sample bytes and parses sandbox reports, emulation reports and event logs. Nothing in the project runs, loads or unpacks a sample. All real-data work uses public reports and pre-extracted features; no binaries are downloaded.

<div class="grid cards" markdown>

- **Try it in 60 seconds**  
  `pip install -e .` and a few commands, no data needed.  
  [Getting started](getting-started.md)
- **How it works**  
  One njRAT report followed through every stage.  
  [Walkthrough](how-it-works.md)
- **Evaluation**  
  Protocols, intervals, ablations, paper reproductions and negative results.  
  [Evaluation](benchmarks.md)
- **Reproduce**  
  Exact commands, run ids, runtimes and expected values.  
  [Reproduce](reproduce.md)
- **Demo reports**  
  Real pipeline output on the bundled fixtures.  
  [Demo](demo/index.md)

</div>

## At a glance

<!-- gen:headline -->
| Question | Data | SPECIMEN [95 % CI] | Baseline | Published |
|---|---|---|---|---|
| Can a static gate skip detonations safely? [^gate] | EMBER 2018, temporal (train Jan-Sep, test Nov-Dec) | skips 72 % of benign, misses 0.6 % of malware; AUC 0.989 [0.989, 0.989] | heuristic AUC 0.51; detonate all: 0 % saved | EMBER LightGBM, 600k rows: AUC 0.996 [^ember] |
| Which family is it? | Avast-CTU CAPEv2, temporal split | 95.0 % [94.6, 95.4] [^fam] | Jaccard: 87.8 % | HMIL: 94.5 % |
| Do Sigma rules from **one** run catch later siblings? | Avast-CTU, 9 families x 10 runs x 5 seeds | recall 0.293 [0.067, 0.560] at 0.006 % cross-family FPR, 0.000 % benign FPR [^rules] | MVP: 0.166 at 1.74 % | none found |
| Is the behaviour malicious? | MalbehavD-V1, 2,570 Cuckoo API traces | 93.4 [90.8, 96.0] % duplicate-free; 96.3 [95.1, 97.4] % on the paper's random splits [^beh] | MVP scorer: 50 % | MalDetConv 96.1 % (random split) |

[^gate]: Standalone `triage-ember` model on EMBER raw features; `analyze` has no PE-to-EMBER extractor and still replays every PE. Threshold for 99 % recall calibrated on October; 5 subsample seeds, 95 % t-intervals (seed variance only).
[^ember]: Upstream benchmark trains on all 600k Jan-Oct rows with EMBER's own features; SPECIMEN uses a 132k-row Jan-Sep subsample and holds October out, so the gap is not drift alone.
[^fam]: Shipped behaviour+static model, chosen on a temporal validation slice; Wilson 95 % interval.
[^rules]: Shipped configuration: packaged negative corpus minus the family the trained model predicts. Mean over 450 runs with a two-level bootstrap CI; the median family is much lower (see Evaluation). Benign FPR is on emulator (Speakeasy) reports, a lower bound.
[^beh]: Shipped API n-gram LR; Nadeau-Bengio corrected 95 % intervals. 42 % of random-split test rows have an exact duplicate in train, which inflates the paper-protocol number.

All cells come from `results/*.json`, produced by the `bench` workflow; each table on the [Evaluation](https://rakshit-737.github.io/specimen-malware-analysis/benchmarks/) page names its run id.
<!-- /gen:headline -->

Details, intervals and caveats: [Evaluation](benchmarks.md).

## Prior art

| Existing | Scope | What SPECIMEN adds |
|---|---|---|
| Cuckoo / CAPEv2 | Dynamic sandboxes that produce behaviour reports | Consumes those reports; adds a provenance graph and ATT&CK timeline, family attribution with token evidence, and specificity-checked rules |
| Any.run / Joe Sandbox | Commercial, closed, cloud | Open, offline, every score explainable |
| VirusTotal / Intezer | Verdicts, code reuse, relationships | Host-level reconstruction and detection synthesis from one run |
| EMBER / HMIL / MalDetConv / Li et al. 2024 | Single-stage classifiers | Published reference points; MalDetConv and Li et al. are re-implemented on their own protocols |
| AutoYara (Raff et al., AISec 2020) | YARA from 10 or fewer samples, measured on held-out family files and benign files | Closest few-sample rule-generation benchmark; SPECIMEN measures behavioural Sigma from one sandbox run against later siblings, other families and benign emulation reports |
| Polygraph / Autograph | Automatic network signatures | Same specificity-versus-generality trade-off, applied to host behaviour |
| yarGen and similar | String-based YARA generation | Behavioural rules filtered against a real negative corpus, with measured sibling recall |
| LLM CTI-to-Sigma generators | Rules from threat-report text | Works from sandbox runs; no published single-run sandbox-to-Sigma benchmark was found |
