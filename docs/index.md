# SPECIMEN

**One sample (or one sandbox report) in, one defensible story out:** what the sample is, what it did on the host, how to detect it next time, and the evidence behind each conclusion.

SPECIMEN is a sample-to-story malware analysis pipeline. It runs an explainable static gate that decides whether a sample is worth detonating, replays recorded sandbox behaviour (CAPEv2/Cuckoo reports, Sysmon exports or its own trace format) into a provenance graph with an ATT&CK timeline, attributes the run to a family, synthesizes YARA and Sigma rules that are checked for specificity, and writes a JSON + Markdown report with a hash manifest.

!!! warning "Lab-only, never executes anything"
    SPECIMEN reads sample bytes and parses sandbox reports and event logs. Nothing in the project runs, loads or unpacks a sample. All real-data work uses public sandbox reports and pre-extracted features; no binaries are downloaded.

## At a glance

| Question | Dataset | SPECIMEN | MVP baseline |
|---|---|---|---|
| Can a static gate skip detonations safely? | EMBER 2018, 56,893 PEs | skips ~42 % of detonations, misses ~1.2 % of malware; AUC 0.994 | detonate everything |
| Which family is it? | Avast-CTU CAPEv2, 48,976 reports, temporal split | 95.9 % accuracy | 87.8 % |
| Do Sigma rules from one run catch later siblings? | Avast-CTU, 10 families x 10 runs | recall 0.33 at 0.016 % FPR | 0.18 at 2.3 % |
| Is the behaviour malicious? | MalbehavD-V1 API traces | ~96-97 % accuracy, AUC 0.99 | 50 % |

Exact numbers, confidence intervals and caveats are on the [Benchmarks](benchmarks.md) page. The [demo reports](demo/index.md) show real pipeline output on the bundled fixtures.

## Where to go next

- [Getting started](getting-started.md): install, run the demo, analyse a report.
- [Architecture](architecture.md): stages and data flow.
- [Datasets](datasets.md): sources, licences, citations.
- [Limitations & roadmap](limitations.md): what is not built, and why.
