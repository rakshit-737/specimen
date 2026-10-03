# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.1] - 2026-10-03

### Fixed
- **Security:** sandbox-controlled strings can no longer form Markdown links or images in reports: every Markdown-structural character is entity-encoded, and protocol-relative and numeric-IPv4 URLs are defanged. A rendering test with the docs-site Markdown extensions guards it.
- **Evidence binding:** a Sysmon export whose event 1 `Hashes` do not include the sample's SHA-256 is refused; traces that record no sample hash are replayed as `unbound` with low confidence (`manifest.trace_binding`). The lab fixture now carries the dummy sample's hash.
- **`analyze` uses the v2 rule synthesizer** with the packaged negative corpus (minus the predicted family), like `report`; it used to emit MVP rules checked only against synthetic negatives.
- Hostile input: `NaN`/`Infinity`/`1e999` numbers, wrong types, deeply nested JSON and malformed XML give one error line or are coerced instead of tracebacks; report files are strict JSON; UTF-16/32 Sysmon exports are read; `batch --workers` must be >= 1 before the ledger is touched.
- Rule synthesis treats `HKCU\Environment`, `Local Settings\MuiCache`, environment variables, system folders and MUI references as generic, so near-generic rules (e.g. `HKEY_CURRENT_USER\Environment\*`) are no longer emitted.
- v1.1.0 shipped without its trained models; they are now attached to the v1.1.0 release with SHA-256s, pinned in `scripts/model_assets.json` and fetched (hash-verified) by `scripts/fetch_models.py`, the docs workflow and the release workflow.

### Changed
- **Rules benchmark:** the true-family exclusion rows are labelled *oracle*; new *shipped* (predicted family left out, out-of-fold family model) and *default install* (no family model) rows; reference runs exclude the packaged corpus's own runs; paired comparisons use family-clustered tests; a candidate-generation ablation row; benign FPR on 32,673 benign Quo Vadis Speakeasy reports (new adapter).
- **Family model:** the open-set abstain threshold is chosen on the temporal validation slice (it was chosen on test) and is now 0.85.
- **Static gate:** the released `triage-ember` model is the temporal model behind the headline; the heuristic baseline is scored on the same temporal test rows; seed t-intervals replace min-max.
- **Paper reproductions:** MalDetConv uses the architecture of its Fig. 10 A-2 (embedding 100, not 10); Li et al. 2024 adds the TF-IDF+PCA rows of its Table I, feature-matched SPECIMEN rows and corrected paired t-tests; no grid search, stated.
- Every result file records its GitHub Actions run id, commit, command and runtime; all suites run in the `bench` workflow; README and docs tables are generated from `results/*.json` and checked in CI.
- Docs: How-it-works numbers come from the regenerated demo, the reproduce page lists run ids and runtimes, CITATION.cff and the data citations are corrected and completed (Avast-CTU authors, Oliveira 2019, Li et al. 2024, both Mal-API-2019 papers, Quo Vadis, AutoYara), AutoYara and Polygraph/Autograph added to prior art, the MkDocs 2.0 banner is silenced, threat model and security policy updated.
- CI: ruff D1 docstring rules for `specimen/`; release images also get a plain-semver tag and OCI version/revision labels; bench inputs are validated and passed via env; the whole EMBER archive hash is enforced.

## [1.1.0] - 2026-10-02

### Changed
- Rules headline uses the seeded 0.020 % FPR and labels the 0.004 % packaged-corpus row as oracle; THREAT_MODEL updated. (Correction, see Unreleased: the 0.020 % row also removed the true family from its negatives, so it was an oracle setting too, and the 'shipped' configuration had not been measured.)
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
