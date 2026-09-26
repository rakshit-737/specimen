# CLI reference

`specimen` (or `python -m specimen`) has six sub-commands.

| command | what it does |
|---|---|
| `specimen triage SAMPLE` | Static triage of sample bytes only (heuristic gate with contributions). |
| `specimen analyze SAMPLE [--trace RUN] [--out DIR] [--force-detonate]` | Full pipeline on sample bytes plus a recorded run: native trace JSON, CAPE/Cuckoo JSON or a Sysmon XML / JSON-lines export. The trace's `sample_sha256` must match the sample. |
| `specimen report REPORT [--out DIR]` | Report-only analysis of a CAPE/Cuckoo JSON report: PE-metadata gate, provenance, behaviour score, family attribution, Sigma + YARA. |
| `specimen batch DIR [--out DIR] [--workers N]` | Queue every `*.json` report in a directory; resumable `jobs.jsonl` ledger with per-job failure isolation. |
| `specimen triage-ember FEATURES.jsonl` | Trained EMBER LightGBM gate with TreeSHAP on EMBER raw-feature JSON lines. |
| `specimen demo [--out DIR]` | Generate inert fixtures and run all demo scenarios. |

Environment variables: `SPECIMEN_MODELS` (model directory, default `models`), `SPECIMEN_DATA` (dataset root for benchmarks).

## Report schema (top level)

| key | content |
|---|---|
| `verdict` | label, fused score, confidence (static/behaviour agreement) |
| `static` | gate score, detonate decision, top contributions |
| `behavior` | probability, `scorer` used, contributions, family + evidence tokens |
| `timeline`, `techniques` | ATT&CK-tagged events with anomaly scores |
| `graph` | node/edge counts and a Mermaid provenance graph |
| `iocs`, `detections` | IOCs, YARA and Sigma rules, specificity notes |
| `manifest` | sample, trace and report hashes, versions, execution mode |
