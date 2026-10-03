# CLI reference

`specimen` (or `python -m specimen`) has six sub-commands.

| command | what it does |
|---|---|
| `specimen triage SAMPLE` | Static triage of sample bytes only (heuristic gate with contributions). |
| `specimen analyze SAMPLE [--trace RUN] [--out DIR] [--force-detonate]` | Full pipeline on sample bytes plus a recorded run: native trace JSON, CAPE/Cuckoo JSON or a Sysmon XML / JSON-lines export (UTF-8/16/32). A trace that records a sample hash (native `sample_sha256`, CAPE `target.file.sha256`, Sysmon event 1 `Hashes` SHA256) must match the sample; a trace without one is replayed as `unbound` with low confidence. Sigma comes from the same v2 synthesizer and negative corpus as `report`. |
| `specimen report REPORT [--out DIR]` | Report-only analysis of a CAPE/Cuckoo JSON report: PE-metadata gate, provenance, behaviour score, family attribution, Sigma + YARA. |
| `specimen batch DIR [--out DIR] [--workers N]` | Queue every `*.json` report in a directory; resumable `jobs.jsonl` ledger with per-job failure isolation. `N` must be >= 1. |
| `specimen triage-ember FEATURES.jsonl` | Trained EMBER LightGBM gate with TreeSHAP on EMBER raw-feature JSON lines. |
| `specimen demo [--out DIR]` | Generate inert fixtures and run all demo scenarios. |

Environment variables:

| variable | default | meaning |
|---|---|---|
| `SPECIMEN_MODELS` | `models` | directory with the optional family and EMBER models (`family_*`, `static_*` release assets) |
| `SPECIMEN_MAX_INPUT_MB` | `512` | largest report or trace file read; bigger inputs are refused before parsing |
| `SPECIMEN_DATA` | `data` | dataset root for the benchmark and download scripts |

Exit codes: 0 success, 1 malformed or mismatched input (one `specimen: error: ...` line, no traceback), 2 usage errors and missing files. Report `.json` files are strict JSON (no `NaN`/`Infinity`).

## Report schema (top level)

| key | content |
|---|---|
| `verdict` | label, fused score, confidence (static/behaviour agreement) |
| `static` | gate score, detonate decision, top contributions |
| `behavior` | probability, `scorer` used, contributions, family + evidence tokens |
| `timeline`, `techniques` | ATT&CK-tagged events with anomaly scores |
| `graph` | node/edge counts and a Mermaid provenance graph |
| `iocs`, `detections` | IOCs, YARA and Sigma rules, specificity notes |
| `manifest` | sample, trace and report hashes, versions, execution mode, `trace_binding` (`analyze`), `negative_corpus` (packaged corpus used and the family left out) |
