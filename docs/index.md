# SPECIMEN

**Contribution, in one sentence:** SPECIMEN measures, on a temporal split of 48,976 CAPEv2 reports, how often Sigma rules synthesised from one sandbox run and filtered against a real negative corpus catch later siblings (mean recall 0.30, median family 0.06), inside one explainable sample-to-report pipeline. Generalising beyond exact values adds only about 0.6 recall points; the negative corpus does most of the work.

[![njRAT demo report](figures/demo.png)](demo/avast_njrat_1.md)

**One sample (or one sandbox report) in, one defensible story out:** what the sample is, what it did on the host, how to detect it next time, and the evidence behind each conclusion.

!!! warning "Lab-only, never executes anything"
    SPECIMEN reads sample bytes and parses sandbox reports and event logs. Nothing in the project runs, loads or unpacks a sample. All real-data work uses public sandbox reports and pre-extracted features; no binaries are downloaded.

<div class="grid cards" markdown>

- **Try it in 60 seconds**  
  `pip install -e .` and two commands, no data needed.  
  [Getting started](getting-started.md)
- **How it works**  
  One njRAT report followed through every stage.  
  [Walkthrough](how-it-works.md)
- **Evaluation**  
  Protocols, intervals, ablations, paper reproductions and negative results.  
  [Evaluation](benchmarks.md)
- **Reproduce**  
  Exact commands, runtimes, which runs need GitHub Actions.  
  [Reproduce](reproduce.md)
- **Demo reports**  
  Real pipeline output on the bundled fixtures.  
  [Demo](demo/index.md)

</div>

## At a glance

<!-- glance -->
| Question | Dataset | SPECIMEN | Baseline (MVP) | Published reference |
|---|---|---|---|---|
| Can a static gate skip detonations safely? | EMBER 2018, **temporal** (train Jan-Sep, test Nov-Dec), 5 subsample seeds | Skips **72 %** of benign and misses **0.6 %** of malware at a 99 %-recall threshold calibrated on October (36 % of all test detonations at EMBER's malware share); ROC AUC **0.989**, TPR **0.49** at 0.1 % FPR. A random split of the same data gives 0.997 / 0.85, so drift costs a lot | Detonate every PE (0 % saved); heuristic AUC 0.560 | Upstream EMBER-2018 LightGBM, 600k rows: AUC 0.9964, TPR 0.868 at 0.1 % FPR |
| Which family is it? | Avast-CTU CAPEv2, 48,976 reports, temporal split | **95.0 %** [94.6, 95.4] accuracy for the shipped behaviour+static model, chosen on a validation slice (behaviour-only scores 95.9 % on test, McNemar p ≈ 1.3e-12); 92.5 % on test reports whose behaviour was never seen in training | Jaccard over ATT&CK sets: 87.8 % | HMIL (behaviour+static): 94.5 % |
| Do auto-Sigma rules from **one** run catch later siblings? | Avast-CTU, 9 families x 10 runs x 5 seeds (HarHar has no host actions) | Mean sibling recall **0.30** [0.08, 0.57] at **0.020 %** [0.002, 0.043] cross-family FPR (ladder + real negatives; 0.004 % if the true family is excluded from the negatives, an oracle setting); the **median family is only 0.06**: Swisyn and Qakbot carry the mean | MVP: 0.17 at 1.8 % FPR | none found for single-run sandbox-to-Sigma |
| Is the behaviour malicious? | MalbehavD-V1, 2,570 Cuckoo API traces | **96.3 ± 1.1 %** accuracy over 5 random 70/30 splits (paper protocol; 42 % of test rows have an exact duplicate in train). **93.4 ± 2.6 %** on a duplicate-free split. Through the shipped pipeline routing: 96.0 ± 1.3 % | MVP synthetic-trained scorer: 50 % (AUC 0.23) | MalDetConv 96.1 %, MalDy 95.6 % (both random split, duplicates included) |
<!-- /glance -->

Details, intervals and caveats: [Evaluation](benchmarks.md).

## Prior art

| Existing | Scope | What SPECIMEN adds |
|---|---|---|
| Cuckoo / CAPEv2 | Dynamic sandboxes that produce behaviour reports | Consumes those reports; adds a static gate with a measured cost/miss trade-off, a provenance graph and ATT&CK timeline, family attribution with token evidence, and specificity-checked rules |
| Any.run / Joe Sandbox | Commercial, closed, cloud | Open, offline, every score explainable |
| VirusTotal / Intezer | Verdicts, code reuse, relationships | Host-level reconstruction and detection synthesis from one run |
| EMBER / HMIL / MalDetConv / Li et al. 2024 | Single-stage classifiers | Published reference points; MalDetConv and Li et al. are reproduced |
| yarGen and similar | String-based YARA generation | Behavioural Sigma from sandbox actions, filtered against a real negative corpus, with measured sibling recall (the ladder adds only ~0.6 points) |
| LLM CTI-to-Sigma generators | Rules from threat-report text | Works from sandbox runs; no published single-run sandbox-to-Sigma benchmark was found |
