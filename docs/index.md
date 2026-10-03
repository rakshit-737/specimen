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
