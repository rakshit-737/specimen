# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

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
