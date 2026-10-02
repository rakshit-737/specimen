# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-02

### Changed
- Rules headline uses the non-oracle seeded 0.020 % FPR; the oracle 0.004 % row is labelled as such; THREAT_MODEL updated.
- Static-gate headline states that `analyze` still detonates every PE.

### Added
- Temporal EMBER-2018 evaluation in GitHub Actions (train Jan-Sep, calibrate Oct, test Nov-Dec, 5 seeds): AUC 0.989, TPR 0.49 at 0.1 % FPR. Worse than the earlier random-split 0.994 / 0.84, and published as such.
- Mal-API-2019 cross-dataset transfer, a reproduction of Li et al. 2024, Oliveira within-dataset results and a MalDetConv reproduction (`results/api_cross.json`, `results/repro_maldetconv.json`).
- Duplicate-free MalbehavD protocol (93.4 %, against 96.3 % on random splits) and pipeline-path accuracy.
- Seeded rule benchmark with ablations, family variant chosen on a validation slice, and an open-set abstain threshold.
- Manual `bench` workflow; CI runs the README quickstart, a wheel test, pip-audit and py3.10-3.14.
- Docs: How it works, Reproduce, the benign-corpus search, a hero screenshot, and repo templates plus CITATION.cff.

### Fixed
- The API behaviour model ships as package data (pip installs used to fall back to the MVP scorer).
- Untrusted strings are escaped in Sigma, YARA and Markdown, Sigma wildcards are emitted correctly, and inputs over 512 MB are refused.
- Samples over 50 MB are hashed in full. Downloads are verified against pinned hashes and mismatches quarantined.
- IOC defanging no longer touches technique IDs or numbers.
- CIs over repeated splits use the Nadeau-Bengio correction.

## [1.0.0] - 2026-09-26

Closes the feasible roadmap gaps and adds docs, container image and releases.

### Added
- **Real-data behaviour scorer in the pipeline**: the MalbehavD-V1 API
  uni+bigram TF-IDF + LR model is exported to `models/api_behaviour.json`
  and evaluated in pure Python (core stays stdlib-only). It is used when a
  trace carries at least 20 real API calls; the report's `behavior.scorer`
  says which scorer ran.
- **Sysmon adapter** (`specimen/adapters/sysmon.py`): Sysmon XML
  (`wevtutil /f:xml`, `ToXml()`) and JSON-lines exports to the trace
  format; `specimen analyze --trace` detects them automatically. DTDs are
  refused.
- **Rule validation**: every emitted Sigma rule is parsed and converted by
  pySigma and every YARA rule compiled by yara-python in a CI job.
- **Confidence intervals and seeds**: bootstrap 95 % CIs on holdout
  metrics; EMBER gate over 5 re-split seeds; MalbehavD over 5 seeds x 70/30
  and 5 x 5-fold CV (95 % t-intervals).
- MkDocs Material docs site on GitHub Pages with API reference and static
  demo reports (`scripts/build_demo.py`).
- Dockerfile (slim, non-root), release workflow publishing
  `ghcr.io/rakshit-737/specimen` and wheel/sdist on `v*` tags.

### Changed
- MalbehavD headline is now the seed-averaged 96.3 ± 0.6 % (the seed-0
  split alone gave 96.8 %, at the lucky end of the spread).
- Mermaid edge labels are quoted.

### Fixed
- `specimen.__version__` reported 0.1.0 while the package was 0.2.0; a
  test now keeps them in sync.

## [0.2.0] - 2026-09-26

The pipeline now runs on real public data.

### Added
- **Real datasets**: resumable, checksummed downloader
  (`scripts/download_data.py`) for the Avast-CTU Public CAPEv2 reduced
  reports (48,976 runs, 10 families), an EMBER 2018 v2 raw-feature prefix,
  and MalbehavD-V1 API sequences. Only reports and features are downloaded,
  never binaries.
- **Adapters**: CAPEv2/Cuckoo full and reduced reports to the trace format,
  and API-call sequences to the trace format. New event types:
  `api_call`, `mutex_create`, `registry_read`, `registry_delete`,
  `service_start`.
- **ATT&CK mapping** for API-level behaviour (anti-debug, keylogging,
  credential access, injection, discovery and more), startup-folder and
  Winlogon persistence, and `wbadmin` recovery inhibition.
- **Static gate on EMBER**: EMBER v2-style vectoriser, LightGBM with
  TreeSHAP explanations, and a detonation threshold calibrated for 99 %
  malware recall (`specimen triage-ember`).
- **Report-only analysis** (`specimen report <cape.json>`): a PE-metadata
  static gate, provenance graph and timeline, behaviour scoring, family
  attribution with per-token evidence, and specificity-checked Sigma and
  YARA rules.
- **Detection synthesis v2** (`specimen/detect.py`): a wildcard
  generalisation ladder that keeps the most general rule with zero hits on
  a negative corpus, plus YARA over `pe.imphash()` and the rarest imports.
- **Batch job queue** (`specimen batch`): a resumable `jobs.jsonl` ledger
  with per-job failure isolation.
- **Benchmarks** (`benchmarks/`) with committed results and figures: static
  gate vs the MVP heuristic, family attribution vs the MVP Jaccard matcher
  and published HMIL numbers, rule generalisation to sibling samples, and
  behavioural detection on MalbehavD-V1.
- LICENSE (MIT), CONTRIBUTING, ADRs 0001-0004, ruff configuration, an
  `[ml]` extra, and `realdata`/`ml` pytest markers.

### Changed
- `analyze --trace` also accepts CAPE/Cuckoo reports. The evidence binding
  (`sample_sha256`) is enforced for them too.
- Timeline anomaly scores are aligned with the events that actually appear
  in the timeline (API calls without a technique are skipped).
- Real reports are never attributed to the synthetic MVP family prototypes.

## [0.1.0] - 2026-09-26

### Added
- MVP: explainable static triage gate, trace replay, provenance graph and
  ATT&CK timeline, synthetic-corpus behaviour scorer, YARA and Sigma
  synthesis with a benign specificity check, JSON and Markdown report with a
  hash manifest, and demo fixtures.
