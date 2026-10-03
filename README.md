# SPECIMEN

[![ci](https://github.com/rakshit-737/specimen/actions/workflows/ci.yml/badge.svg)](https://github.com/rakshit-737/specimen/actions/workflows/ci.yml)
[![docs](https://github.com/rakshit-737/specimen/actions/workflows/docs.yml/badge.svg)](https://rakshit-737.github.io/specimen/)
![python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.14-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![core deps](https://img.shields.io/badge/core-stdlib%20only-lightgrey)

**Docs:** <https://rakshit-737.github.io/specimen/> (architecture, evaluation with confidence intervals, API reference, [demo reports](https://rakshit-737.github.io/specimen/demo/)) · **Image:** `ghcr.io/rakshit-737/specimen`

**Contribution, in one sentence:** SPECIMEN measures, on a temporal split of 48,976 CAPEv2 reports and on 32,673 benign emulation reports, how often Sigma rules synthesised from *one* sandbox run and checked against a real negative corpus catch later siblings without firing on other families or on benign software, inside one explainable sample-to-report pipeline; the ablation separates what candidate generation, the generalisation ladder and the negative corpus each contribute.

[![njRAT demo report: verdict, provenance graph and a synthesised Sigma rule](docs/figures/demo.png)](https://rakshit-737.github.io/specimen/demo/avast_njrat_1/)

**One sample (or one sandbox report) in, one defensible story out:** what the sample is, what it did on the host, how to detect it next time, and the evidence behind each conclusion.

SPECIMEN replays sandbox behaviour (CAPEv2/Cuckoo reports, Sysmon exports or its own trace format) into a process/file/registry/network provenance graph with an ATT&CK timeline, attributes the run to a family, synthesises YARA and Sigma rules that are checked for specificity before they are kept, and writes a JSON + Markdown report with a hash manifest. A static gate scores the sample first; a trained EMBER gate is available as a standalone command.

> **Lab-only, and it never executes anything.** SPECIMEN reads sample bytes and parses sandbox reports. Nothing in this repository runs, loads or unpacks a sample. All real-data work uses public sandbox reports, emulation reports and pre-extracted features: no binaries are ever downloaded. See [Safety](#safety).

---

## Headline results (real public data)

<!-- gen:headline -->
<!-- /gen:headline -->

## Architecture

```mermaid
flowchart LR
  S["Sample bytes<br/>read-only"] --> G["Static gate<br/>MVP heuristic (every PE replayed)"]
  EF["EMBER raw features"] --> GE["triage-ember<br/>LightGBM + TreeSHAP (standalone)"]
  R["CAPEv2 / Cuckoo report<br/>Sysmon export, native trace"] --> A["Adapters<br/>CAPE, Sysmon, API sequence, Speakeasy"]
  R -. "static.pe" .-> G2["PE-metadata gate"]
  G -->|"detonate?"| D{"score >= threshold<br/>or --force-detonate"}
  D -->|"yes: replay recorded run"| A
  D -->|"no"| REP
  A --> TR["Trace<br/>typed, validated events, bound to the sample hash"]
  TR --> PROV["Provenance graph<br/>+ ATT&CK timeline + anomaly"]
  TR --> TOK["Normalised tokens"]
  TOK --> FAM["Family model<br/>hashed tokens + LR, per-token evidence"]
  TR --> SC["Behaviour scorer<br/>API n-gram LR, MVP fallback"]
  TR --> SYN["Detection synthesis v2<br/>Sigma ladder, YARA imphash / rare imports"]
  FAM -. "predicted family left out" .-> NEG
  NEG[("Packaged negative corpus<br/>Avast-CTU train runs + synthetic benign")] --> SYN
  G2 --> REP
  PROV --> REP["Unified report<br/>verdict, confidence, graph, timeline,<br/>IOCs, rules, manifest hashes"]
  FAM --> REP
  SC --> REP
  SYN --> REP
  Q[["batch job queue<br/>jobs.jsonl ledger"]] -.-> R
```

| Stage | Module | Notes |
|---|---|---|
| Adapters | `specimen/adapters/cape.py`, `sysmon.py`, `api_seq.py`, `speakeasy.py` | Full CAPE/Cuckoo call logs, Avast-CTU reduced reports, Sysmon XML / JSON-lines exports (UTF-8/16/32), API sequences and Speakeasy emulation reports, all mapped to one `Trace`. Hostile input is coerced and capped; XML with DTDs is refused; non-finite numbers and deep nesting are rejected with one error line. |
| Evidence binding | `specimen/pipeline.py` | A trace that records a sample hash (native `sample_sha256`, CAPE `target.file.sha256`, Sysmon event 1 `Hashes`) must match the sample; one without is replayed as `unbound` with low confidence. |
| Behaviour scorer | `specimen/api_behaviour.py`, `specimen/scoring.py` | MalbehavD-V1 API uni+bigram TF-IDF + LR, exported to JSON and run in pure Python when a trace has >= 5 real API calls; otherwise the MVP ATT&CK-feature scorer. The report names the scorer used. |
| Static gate | `specimen/static_triage.py`, `specimen/ml/ember.py` | `analyze` uses the additive heuristic and still replays every PE. The EMBER LightGBM gate (TreeSHAP, 99 %-recall threshold) runs only through `triage-ember` on EMBER raw-feature JSON: there is no PE-to-EMBER feature extractor, so the integrated pipeline saves 0 % of PE detonations today. |
| Provenance | `specimen/provenance.py` | Process tree, file/registry/network/mutex/service edges; about 50 ATT&CK mapping rules |
| Tokens | `specimen/tokens.py` | Removes user names, GUIDs, SIDs, hex blobs and numbers so runs of one family share tokens |
| Family | `specimen/ml/family.py` | 2^18 hashed tokens with multinomial LR, stored as `.npz` (no pickle); every prediction is explained by its top tokens; below the open-set threshold the report says `unknown (closest: X)` |
| Detection synthesis | `specimen/detect.py` (v2, used by `analyze` and `report`), `specimen/synth.py` (MVP baseline) | See [ADR 0002](docs/adr/0002-specificity-constrained-rule-generalisation.md) |
| Report | `specimen/report.py` | JSON (strict, no NaN) + Markdown (every report string entity-encoded, IOCs defanged), Mermaid graph, manifest with sample, trace, report and content SHA-256 |
| Queue | `specimen/jobqueue.py` | Resumable append-only ledger with per-job failure isolation |

## Try it in 60 seconds

Core install is stdlib-only, so this needs nothing but Python 3.10+:

<!-- quickstart:start -->
```bash
git clone https://github.com/rakshit-737/specimen && cd specimen
pip install -e .
python -m specimen demo --out out
python -m specimen report tests/fixtures/cape/avast_njrat_1.json --out out/reports
python -m specimen batch tests/fixtures/cape --out out/batch --workers 2
python -m specimen analyze tests/fixtures/sysmon/lab_sample.bin --trace tests/fixtures/sysmon/lab_run.xml --force-detonate --out out/sysmon
```
<!-- quickstart:end -->

CI runs this block exactly as written on every push. `lab_sample.bin` is an inert dummy file; the Sysmon fixture records its SHA-256 in event 1 `Hashes`, so `analyze` refuses any other sample with that trace.

Without the trained models (the default for a plain `pip install` and the Docker image) the report's `family` is `null`, nothing is left out of the negative corpus (so fewer Sigma rules survive; see Evaluation 3), and reduced reports, which have no API call log, are scored by the MVP ATT&CK-feature scorer. The API behaviour model always ships inside the package.

## Usage

```bash
pip install -e ".[dev,ml]"       # [ml] adds numpy/scikit-learn/lightgbm for the trained models
python -m pytest -q

# trained family model and EMBER gate (too large for git): release assets, SHA-256 pinned in scripts/model_assets.json
python scripts/fetch_models.py --dest models            # verifies every hash; or, without a clone:
gh release download -R rakshit-737/specimen -p 'family_*' -p 'static_*' -D models   # latest release

python -m specimen analyze <your-sample> --trace <recorded-run.json|sysmon.xml> --out out/
python -m specimen batch <your-report-dir> --out out/batch --workers 4
python -m specimen triage-ember <ember-raw-features.jsonl>
```

In Docker: `docker run --rm --network none -v "$PWD/tests/fixtures:/fx:ro" ghcr.io/rakshit-737/specimen:latest report /fx/cape/avast_njrat_1.json` (pin a release with `:v1.1.0`; releases after 1.1.0 are also tagged with the plain version, e.g. `:1.2.0`. The image has no family or EMBER model: mount them with `-v ./models:/opt/specimen/models:ro`).

Example: `specimen report` on the bundled njRAT report with the pinned family model in `models/` (actual output):

<!-- gen:demo-example -->
<!-- /gen:demo-example -->

The bundled fixtures are trimmed to about 8 KB, so they carry fewer behaviour tokens than the full reports the model was evaluated on. Each report contains the static contributions, the timeline with ATT&CK tags and anomaly scores, the provenance graph as Mermaid, IOCs, the family evidence tokens, ready-to-review Sigma and YARA rules, and the evidence manifest.

## Data

Nothing is committed. `scripts/download_data.py` fetches the data into `$SPECIMEN_DATA` (outside the repo) with resumable parallel range requests and records SHA-256 hashes in `SHA256SUMS` (`--verify` re-checks them against the pinned values); downloads over 1 GB (the whole EMBER archive, the Speakeasy reports) run only inside the GitHub Actions `bench` workflow.

| Dataset | What is used | Size | Licence | Citation |
|---|---|---|---|---|
| [Avast-CTU Public CAPEv2 Dataset](https://github.com/avast/avast-ctu-cape-dataset) | Reduced reports (`behavior.summary` + `static.pe`) for 48,976 samples in 10 families, labels and dates | 593 MB zip | MIT (per `Licences.txt`) | Bošanský et al. 2022 |
| [EMBER 2018 v2](https://github.com/elastic/ember) | Raw feature JSON lines; locally a 120 MB prefix (2018-01), the whole archive (pinned SHA-256 `b6052eb8...7812`) only in Actions | 1.7 GB | MIT | Anderson & Roth 2018 |
| [Quo Vadis Speakeasy](https://huggingface.co/datasets/dtrizna/quovadis-speakeasy) | The **benign** emulation reports only (`report_clean` + `report_windows_syswow64`, train and test: 32,673 reports), pinned revision, fetched only in Actions | ~1.6 GB | Apache-2.0 | Trizna 2022 |
| [Mal-API-2019](https://github.com/ocatak/malware_api_class) | 7,107 Cuckoo API-call sequences in 8 malware families (2.17 GB text, streamed from the zip) | 12 MB zip | MIT | Catak & Yazı 2019; Catak et al. 2020 |
| Oliveira API-call sequences (public re-host of the 2019 Kaggle / IEEE DataPort release) | 42,797 malware + 1,079 goodware, first 100 calls, integer-coded | 15 MB | not stated by the re-host; within-dataset evaluation only | Oliveira 2019 |
| [MalbehavD-V1](https://github.com/mpasco/MalbehavD-V1) | Cuckoo API-call sequences, 1,285 benign + 1,285 malicious | 2.3 MB | MIT | Maniriho et al. 2022 |

```bash
export SPECIMEN_DATA=/data/specimen           # anywhere outside the repo
python scripts/download_data.py --dest "$SPECIMEN_DATA"
python scripts/download_data.py --dest "$SPECIMEN_DATA" --verify
```

The test fixtures in `tests/fixtures/cape/` are four real Avast-CTU reduced reports trimmed to about 8 KB each (reports only), plus one clearly synthetic full-format CAPE report.

## Evaluation

Every number below is generated by `scripts/render_results.py` from `results/*.json`, and every result file comes from the GitHub Actions `bench` workflow (its run id and commit are in the file and under each table). Exact commands, runtimes and expected values are on the [Reproduce](https://rakshit-737.github.io/specimen/reproduce/) page; protocols and caveats are on the [Evaluation](https://rakshit-737.github.io/specimen/benchmarks/) page.

### 1. Static gate on EMBER (standalone `triage-ember`; `analyze` does not call it)

Train Jan-Sep 2018, calibrate the 99 %-recall threshold on October, test Nov-Dec; month-stratified subsample of the official archive, SPECIMEN's own 2,440-dimension featuriser, 5 seeds. The seed-0 model is the released `static_*` asset.

<!-- gen:static-temporal -->
<!-- /gen:static-temporal -->

On the same Nov-Dec months the upstream model (all 600k labelled Jan-Oct rows, EMBER's own features) reaches a far higher TPR at 0.1 % FPR; SPECIMEN's gate uses a fifth of the rows, its own featuriser and no October training data, so the gap mixes volume and features with drift. "Detonations saved" depends on the malware share of the submissions (benign share x benign skipped + malware share x malware missed).

<details><summary>Earlier one-month random split (optimistic about drift)</summary>

<!-- gen:static-random -->
<!-- /gen:static-random -->

</details>

### 2. Family attribution on Avast-CTU CAPEv2

Authors' temporal split: 37,512 training reports before 2019-08-01, 11,464 later test reports. "Novel behaviour" = test reports whose behaviour-token set never occurs in training. The shipped variant and the open-set threshold are both chosen on a validation slice (training runs from 2019-06 on), never on test.

<!-- gen:family -->
<!-- /gen:family -->

**Open set.** The abstain threshold is chosen on the validation slice and applied unchanged to test:

<!-- gen:family-openset -->
<!-- /gen:family-openset -->

### 3. Do auto-rules from ONE run generalise? `results/rules_avast.json`

For each family and seed (5 seeds), 10 reference runs are drawn from the training split (never one of the runs inside the packaged corpus), rules are synthesised from each single run, and they are applied to the later test split and to the benign Speakeasy reports. *Sibling recall* is the share of same-family test runs on which any rule fires; *cross-family FPR* the same share over other-family test runs. Rows marked **oracle** remove the true family from the negatives, which the product cannot do; the **shipped** row removes the family the trained model predicts (out-of-fold, 5-fold cross-fitted), as `analyze` and `report` do.

<!-- gen:rules -->
<!-- /gen:rules -->

<img src="docs/figures/rule_generalisation.png" width="640" alt="Sibling recall against cross-family FPR (log scale) per synthesizer, with 95 % CIs">

What the ablation shows:

<!-- gen:rules-findings -->
<!-- /gen:rules-findings -->

<details><summary>Family-clustered paired tests</summary>

<!-- gen:rules-tests -->
<!-- /gen:rules-tests -->

</details>

### 4. Behavioural detection on MalbehavD-V1

Every sample goes through `api_sequence_to_trace`. 70/30 splits as in the dataset paper, 5x5-fold CV, and a duplicate-free split.

<!-- gen:behaviour -->
<!-- /gen:behaviour -->

The MVP's synthetic-trained scorer does not transfer: API-only traces trigger almost no ATT&CK-mapped features.

### 5. Paper reproductions: paper vs reproduction vs SPECIMEN

**MalDetConv (Maniriho et al. 2022) on MalbehavD-V1** (`benchmarks/repro_maldetconv.py`). Re-implemented in PyTorch from the paper: the architecture is taken from Fig. 10 A-2 (p. 17 of arXiv:2209.03547v1; embedding 100, Conv1D 128x8 with dropout 0.2, Conv1D 64x5, max pooling, BiGRU 120, dense 150/100/60/15, sigmoid; Adam 0.001, binary cross-entropy), Keras-style pre-padding and truncation to n calls, random 70/30 split. Pool size, padding mode and batch size use Keras defaults and the epoch count (20) is a guess, because the paper does not state them. The round-3 run had wrongly treated the layer sizes as unstated; its guessed architecture stays as an ablation. The duplicate-free columns keep one row per distinct model input (the last n calls).

<!-- gen:maldetconv -->
<!-- /gen:maldetconv -->

Both are re-implementations rather than exact reproductions: the paper's training schedule and preprocessing details are not fully specified.

**Li et al. 2024 on Mal-API-2019** (`benchmarks/bench_api_cross.py`). 8-class family classification with 5-fold CV; Table I reports TF-IDF and TF-IDF + PCA models, both reproduced on their own features; SPECIMEN's LR runs on the same folds and features.

<!-- gen:li2024 -->
<!-- /gen:li2024 -->

**Cross-dataset.** The shipped MalbehavD-trained scorer applied unchanged to Mal-API-2019 (all malware):

<!-- gen:cross -->
<!-- /gen:cross -->

Cross-dataset transfer to Oliveira is not possible because the re-host has no API-name table.

## Prior art and how SPECIMEN differs

| Existing | Scope | What SPECIMEN adds |
|---|---|---|
| Cuckoo / CAPEv2 | Mature dynamic sandboxes that produce behaviour reports | SPECIMEN *consumes* those reports. It adds a provenance graph and ATT&CK timeline, family attribution with token evidence, and rules that are checked for specificity before they are kept |
| Any.run / Joe Sandbox | Commercial, closed and cloud-based | Open, offline and extendable; every score is explainable |
| VirusTotal / Intezer | Verdicts, code reuse and relationships | Host-level reconstruction and detection synthesis from one run |
| EMBER / HMIL / MalDetConv / Li et al. 2024 | Single-stage classifiers | Published numbers used as reference points; MalDetConv and Li et al. are re-implemented on their own protocols |
| AutoYara (Raff et al., AISec 2020) | YARA rules from 10 or fewer samples of a family, measured on held-out family files and benign files | The closest peer-reviewed few-sample rule-generation benchmark. SPECIMEN targets *behavioural* Sigma from a single sandbox run, measures later-in-time siblings, other families and benign emulation reports, and positions its PE-metadata YARA rows as a baseline rather than a competitor |
| Polygraph / Autograph (Newsome et al. 2005; Kim & Karp 2004) | Automatic network signatures from sample sets | The same specificity-versus-generality trade-off, applied to host behaviour with a negative corpus check |
| yarGen and similar | String-based YARA generation | Behavioural rules, filtered against a real negative corpus, with a measured single-run-to-sibling recall |
| LLM CTI-to-Sigma generators | Rules from threat-report *text* | SPECIMEN works from sandbox runs; no published single-run sandbox-to-Sigma benchmark was found to compare against |

## Limitations

- **No live detonation.** The detonation controller (QEMU/KVM snapshot and revert, egress verification) and live eBPF capture are not built: they need an isolated lab host and must never run on this development machine. SPECIMEN replays recorded runs instead ([ADR 0001](docs/adr/0001-report-replay-instead-of-live-detonation.md)). Binary `.evtx` must be exported to XML first.
- **Reduced reports have no timing.** Events from them are ordered deterministically and flagged `synthetic_ts`.
- **Benign FPR is measured on emulation, not sandbox, reports.** Speakeasy records fewer host actions than CAPE, so the benign FPR is a lower bound; the cross-family FPR uses real sandbox reports of other malware families.
- **Without a family model nothing is left out of the negative corpus**, which costs recall (Evaluation 3); the pip package and Docker image ship without it.
- **The EMBER LightGBM gate is standalone** (`triage-ember` on EMBER raw features). `analyze` has no PE-to-EMBER feature extractor and still replays every PE.
- **Family attribution is closed-set over 10 families**; some unseen-family reports still pass the abstain threshold (Evaluation 2).
- **MalbehavD-V1 contains exact duplicate sequences**; random splits, including the published ones, partly measure memorisation. The duplicate-free number is the honest one.
- **The API behaviour scorer is trained on MalbehavD-V1** (2,570 samples). Reduced reports (no call logs) still use the MVP scorer, which is known to transfer poorly.
- **Paper reproductions are re-implementations**: unstated settings (epochs, batch size, grid-search ranges) are guessed and recorded.
- No adversarial robustness evaluation of any model.

## Roadmap

- [x] Static gate wired into reconstruction on pre-captured logs (CAPE adapters, 49k real runs)
- [x] Detection synthesizer with measured generalisation, used by both `analyze` and `report`
- [x] Unified report with evidence manifest and trace-to-sample binding; batch queue
- [x] Family attribution with an open-set threshold chosen on validation
- [x] Real-data behaviour scorer in the pipeline (API n-grams, pure-Python inference)
- [x] Emitted rules validated with pySigma and yara-python in CI
- [x] Sysmon (XML / JSON lines, UTF-8/16/32) to trace adapter
- [x] Temporal EMBER evaluation on the full 2018 set (GitHub Actions)
- [x] Seeded rule benchmark with ablation and family-clustered tests
- [x] More API-call datasets (Mal-API-2019, Oliveira) and paper reproductions (MalDetConv, Li et al. 2024)
- [x] Benign behaviour corpus for Sigma FP measurement (Quo Vadis Speakeasy adapter)
- [ ] Stage 4: detonation controller with EICAR and benign binaries only, fail-closed without verified egress isolation (needs a lab hypervisor)
- [ ] Live eBPF capture (needs a Linux lab host)
- [ ] PE-to-EMBER feature extraction so `analyze` uses the trained gate
- [ ] Benign *sandbox* (CAPE) reports for a tighter benign FPR
- [ ] Adversarial robustness checks

## Safety

- SPECIMEN only reads bytes (capped at 50 MB) and parses JSON/XML. There is no code path that executes, imports, unpacks or decompresses a sample.
- No binaries are downloaded: only sandbox reports, emulation reports, pre-extracted features and labels. `.gitignore` blocks `samples/`, `*.exe`, `*.dll`, `*.zip`, `data/` and `models/`.
- Model artefacts are stored as LightGBM text and `.npz` files with pinned SHA-256s. Loading a model never unpickles anything.
- Auto-generated rules are `status: experimental`. They record their generalisation rung and must be reviewed before deployment.
- Any future detonation work must run in a disposable VM with no egress and be reverted after each run. See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).

## Project docs

[Docs site](https://rakshit-737.github.io/specimen/) · [CHANGELOG](CHANGELOG.md) · [CONTRIBUTING](CONTRIBUTING.md) · [ADRs](docs/adr/) · [Threat model](THREAT_MODEL.md) · [Security policy](SECURITY.md) · [Citation](CITATION.cff)

## Citation of the data and papers

```
Bošanský B., Kouba D., Maňhal O., Sick T., Lisý V., Křoustek J., Somol P. Avast-CTU Public CAPE Dataset. arXiv:2209.03188, 2022.
Anderson H. S., Roth P. EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. arXiv:1804.04637, 2018.
Trizna D. Quo Vadis: Hybrid Machine Learning Meta-Model Based on Contextual and Behavioral Malware Representations. AISec 2022, doi:10.1145/3560830.3563726.
Maniriho P., Mahmood A. N., Chowdhury M. J. M. MalDetConv. arXiv:2209.03547, 2022; API-MalDetect, JNCA 218:103704, 2023, doi:10.1016/j.jnca.2023.103704 (MalbehavD-V1).
Catak F. O., Yazı A. F. A Benchmark API Call Dataset for Windows PE Malware Classification. arXiv:1905.01999, 2019; Catak F. O., Yazı A. F., Elezaj O., Ahmed J. PeerJ Computer Science 6:e285, 2020, doi:10.7717/peerj-cs.285 (Mal-API-2019).
Oliveira A. Malware Analysis Datasets: API Call Sequences. IEEE DataPort, 2019, doi:10.21227/tqqm-aq14 (fetched from a public re-host; see docs/datasets.md).
Li Z., Zhu H., Liu H., Song J., Cheng Q. Comprehensive evaluation of Mal-API-2019 dataset by machine learning in malware detection. IJCSIT 2(1), 2024, doi:10.62051/ijcsit.v2n1.01.
Raff E. et al. Automatic Yara Rule Generation Using Biclustering. AISec 2020, doi:10.1145/3411508.3421372.
```

MIT licensed. See [LICENSE](LICENSE).
