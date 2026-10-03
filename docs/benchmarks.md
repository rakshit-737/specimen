# Evaluation

## Methodology

- **Traceability.** Every number comes from a script in `benchmarks/`, run by the GitHub Actions `bench` workflow, and a JSON file in [`results/`](https://github.com/rakshit-737/specimen-malware-analysis/tree/main/results) whose `provenance` block names the run id, job, commit, command and runtime. The tables on this page and in the README are generated from those files by `scripts/render_results.py` (CI fails if they drift), and every value is rounded once, there. See [Reproduce](reproduce.md).
- **Splits.** Avast-CTU uses the authors' temporal split (train before 2019-08-01). EMBER uses a temporal split (train Jan-Sep 2018, calibrate Oct, test Nov-Dec) plus the earlier one-month random split. MalbehavD uses the paper's random 70/30 split and duplicate-free splits.
- **Model selection.** The family variant and its open-set threshold are chosen on a temporal validation slice (training runs from 2019-06), never on test. The rule benchmark's "shipped" row uses out-of-fold family predictions, so no reference run is scored by a model that saw it.
- **Leakage controls.** Exact-duplicate analysis (MalbehavD, Mal-API), duplicate-free protocols (on the model input for MalDetConv), "novel behaviour" subsets (Avast-CTU), and reference runs drawn outside the packaged negative corpus.
- **Intervals (95 %).** Wilson for proportions; percentile bootstrap over test rows for single holdouts; Nadeau-Bengio corrected resampled t over repeated splits and folds (on the logit scale near 0 or 1, so bounds stay in [0, 1]); t-intervals over seeds where the test rows are fixed (seed variance only); a two-level bootstrap (families, then runs) for rule recall and FPR.
- **Tests.** McNemar for paired classifiers on one test set; Nadeau-Bengio corrected paired t for models compared on the same folds; for the rule ablation, exact Wilcoxon signed-rank and sign-flip permutation tests on the 9 family-mean differences (the 450 runs are clustered within families, so unit-level tests would overstate significance).
- **Negative results are kept**: the MVP scorers, the over-general ladder with synthetic negatives, the closed-set family leak, drift on EMBER, and reproductions that fall short of the papers.

## 1. Static gate on EMBER

The gate evaluated here is the standalone `triage-ember` model on EMBER raw features; `analyze` does not call it (it has no PE-to-EMBER feature extractor and replays every PE).

**Temporal.** The full EMBER-2018 archive is downloaded in Actions (pinned SHA-256 of the whole file), vectorised with SPECIMEN's own featuriser and month-stratified subsampled; train Jan-Sep, threshold calibrated for 99 % malware recall on October, test Nov-Dec; 5 subsample seeds. The baselines are scored on the same test rows.

<!-- gen:static-temporal -->
| protocol | ROC AUC | TPR @ 0.1 % FPR | TPR @ 1 % FPR | detonations saved | malware missed | benign skipped |
|---|---|---|---|---|---|---|
| **temporal, SPECIMEN gate** (5 seeds) | 0.9892 [0.9889, 0.9895] | 0.488 [0.452, 0.524] | 0.873 [0.868, 0.879] | 36.4 % [35.5, 37.3] | 0.63 % [0.52, 0.73] | 72.2 % [70.4, 74.1] |
| same, seed 0, bootstrap over test rows | [0.9888, 0.9898] | [0.425, 0.561] | [0.870, 0.882] |  |  |  |
| MVP heuristic gate, same test rows | 0.510 [0.507, 0.514] | 0.001 | 0.005 | 0.0 % | 0.00 % | 0.0 % |
| detonate every PE (what `analyze` does) | - | - | - | 0 % | 0 % | 0 % |
| random split, same months and volume | 0.9965 [0.9964, 0.9966] | 0.852 [0.843, 0.862] | 0.949 [0.947, 0.951] |  |  |  |
| *upstream EMBER-2018 LightGBM (600k Jan-Oct rows, EMBER features)* | *0.99643* | *0.868* | *0.965* |  |  |  |

Intervals for the 5 seeds are 95 % t-intervals over seeds (seed variance only: the test rows are fixed); the seed-0 row bootstraps the test rows. Source: `results/static_ember_temporal.json` (bench run [37091150763](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37091150763), commit `68dfb7c`).
<!-- /gen:static-temporal -->

<img src="../figures/static_temporal.png" width="480" alt="Per-month TPR and detonations saved on the temporal EMBER test months">

The upstream reference is not like-for-like: it trains on all 600k labelled Jan-Oct rows with EMBER's own 2,381 features, while SPECIMEN uses a 132k-row Jan-Sep subsample, its own featuriser and keeps October for calibration. The gap therefore mixes training volume and features with drift. "Detonations saved" depends on the malware share of the submissions: benign share x benign skipped + malware share x malware missed.

**Earlier one-month random split.** A stratified 25 % of a 56,893-row prefix (2018-01 only); optimistic about drift.

<!-- gen:static-random -->
| model | ROC AUC [bootstrap 95 %] | TPR @ 0.1 % FPR | TPR @ 1 % FPR | accuracy | F1 |
|---|---|---|---|---|---|
| MVP heuristic (ported) | 0.562 [0.553, 0.571] | 0.008 [0.005, 0.011] | 0.018 | 0.525 | 0.490 |
| logistic regression | 0.967 [0.964, 0.971] | 0.006 [0.000, 0.098] | 0.577 | 0.925 | 0.929 |
| LightGBM (SPECIMEN) | 0.994 [0.993, 0.995] | 0.846 [0.812, 0.877] | 0.928 | 0.964 | 0.966 |

Source: `results/static_ember.json` (bench run [37093305708](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37093305708), commit `a575df4`).
<!-- /gen:static-random -->

<img src="../figures/static_roc.png" width="420" alt="ROC curves of the three static gates on EMBER">

Every gate decision carries TreeSHAP contributions over named features, for example `section.n_rx`, `datadir[2].size` or `imports:CreateToolhelp32Snapshot`.

## 2. Family attribution on Avast-CTU CAPEv2

Authors' temporal split: 37,512 training reports before 2019-08-01, 11,464 later test reports. "Novel behaviour" = test reports whose behaviour-token set never occurs in training.

<!-- gen:family -->
| model | test accuracy [Wilson 95 %] | novel-behaviour accuracy | macro-F1 |
|---|---|---|---|
| MVP Jaccard over ATT&CK technique sets | 0.878 [0.872, 0.884] | 0.813 [0.803, 0.822] | 0.713 |
| static.pe tokens only (validation 0.929) | 0.700 [0.692, 0.709] | 0.504 [0.492, 0.515] | 0.744 |
| behaviour tokens only (validation 0.986) | 0.959 [0.955, 0.962] | 0.934 [0.928, 0.940] | 0.926 |
| **behaviour + static tokens (shipped; best on validation, 0.987)** | 0.950 [0.946, 0.954] | 0.925 [0.918, 0.931] | 0.923 |
| *published HMIL behaviour+static (Bosansky 2022)* | *0.945* |  |  |
| *published HMIL static-only (Bosansky 2022)* | *~0.63* |  |  |

McNemar, behaviour-only vs behaviour+static on test: 159 vs 56 discordant reports, p = 1.3e-12. Source: `results/family_avast.json` (bench run [37091150763](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37091150763), commit `68dfb7c`).
<!-- /gen:family -->

<img src="../figures/family_confusion.png" width="440" alt="Confusion matrix of the family model on the temporal test split">

The like-for-like comparison with HMIL (Bošanský et al. 2022) is behaviour+static. Behaviour-only can score higher on test, but choosing it there would mean selecting on the test set, so the published shipped number is the validation-selected variant. Each prediction lists the tokens that drove it.

**Open set.** The abstain threshold is the largest value with at least 95 % known-family coverage on the validation slice (models fitted on earlier runs; leave-one-family-out on validation for unseen families), applied unchanged to test:

<!-- gen:family-openset -->
| split | abstain below | known-family coverage | accuracy on covered | unseen family accepted |
|---|---|---|---|---|
| validation (2019-06..07; chosen here) | 0.85 | 95.4 % | 99.8 % | 26.8 % |
| test (applied unchanged) | 0.85 | 92.4 % [91.9, 92.9] | 99.9 % [99.8, 99.9] | 13.3 % [12.7, 13.9] |

Leave-one-family-out on test: the median top probability of a held-out family's reports is 0.45-0.79. Below the threshold reports say `unknown (closest: X)`. Source: `results/family_avast.json` (bench run [37091150763](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37091150763), commit `68dfb7c`).
<!-- /gen:family-openset -->

## 3. Do auto-rules from ONE run generalise?

For each family and seed (5 seeds), 10 reference runs are drawn from the training split (never one of the 1,800 runs inside the packaged negative corpus), rules are synthesised from each single run, and they are applied to the later test split and to the 32,673 benign Speakeasy reports. *Sibling recall* is the share of same-family test runs on which any rule fires; *cross-family FPR* the same share over other-family test runs; *benign FPR* the share of benign reports. Per-run values are in `results/rules_avast_units.csv`.

Rows marked **oracle** remove the *true* family from the negatives, which the product cannot do. The **shipped** row is what `analyze` and `report` do with the released family model: they remove the family the model *predicts* (here from 5-fold cross-fitted models, so the prediction is out-of-sample). The **default install** row is the pip/Docker package without a family model: nothing is removed.

<!-- gen:rules -->
| synthesizer (ablation) | sibling recall [95 % CI] | median family | novel-behaviour recall | cross-family FPR [95 % CI] | benign FPR (Speakeasy) [Wilson 95 %] | rules / run |
|---|---|---|---|---|---|---|
| Sigma MVP (technique-gated exact values, synthetic negatives) | 0.166 [0.015, 0.401] | 0.005 | 0.183 [0.018, 0.431] | 1.743 % [0.858, 2.752] | 0.000 % [0.000, 0.012] | 0.6 |
| Sigma MVP + real negatives (oracle) | 0.000 [0.000, 0.000] | 0.000 | 0.000 [0.000, 0.000] | 0.000 % [0.000, 0.000] | 0.000 % [0.000, 0.012] | 0.0 |
| every host action, exact values, synthetic negatives | 0.313 [0.092, 0.574] | 0.145 | 0.312 [0.092, 0.568] | 0.813 % [0.378, 1.454] | 0.000 % [0.000, 0.012] | 6.0 |
| every host action, exact values + real negatives (oracle) | 0.292 [0.063, 0.562] | 0.090 | 0.288 [0.061, 0.557] | 0.012 % [0.001, 0.031] | 0.000 % [0.000, 0.012] | 5.4 |
| ladder + synthetic negatives only | 0.362 [0.140, 0.612] | 0.239 | 0.384 [0.163, 0.626] | 9.317 % [3.967, 16.527] | 0.000 % [0.000, 0.012] | 6.0 |
| ladder + 1,500 other-family negatives (true family excluded, oracle) | 0.296 [0.069, 0.565] | 0.090 | 0.292 [0.065, 0.559] | 0.019 % [0.004, 0.039] | 0.000 % [0.000, 0.012] | 5.5 |
| same, at most 3 rules (oracle) | 0.237 [0.052, 0.476] | 0.069 | 0.227 [0.043, 0.460] | 0.009 % [0.001, 0.021] | 0.000 % [0.000, 0.012] | 2.6 |
| packaged corpus, true family excluded (oracle) | 0.293 [0.067, 0.560] | 0.090 | 0.289 [0.064, 0.555] | 0.004 % [0.002, 0.007] | 0.000 % [0.000, 0.012] | 5.5 |
| **packaged corpus, predicted family excluded (shipped)** | 0.293 [0.067, 0.560] | 0.090 | 0.289 [0.064, 0.555] | 0.006 % [0.003, 0.011] | 0.000 % [0.000, 0.012] | 5.5 |
| packaged corpus, no exclusion (default install, no family model) | 0.000 [0.000, 0.000] | 0.000 | 0.000 [0.000, 0.001] | 0.001 % [0.000, 0.002] | 0.000 % [0.000, 0.012] | 2.4 |
| ladder + other-family negatives, 5 runs pooled (oracle) | 0.380 [0.148, 0.635] | 0.342 | 0.364 [0.123, 0.620] | 0.042 % [0.005, 0.102] | 0.000 % [0.000, 0.012] | 5.6 |
| YARA `pe.imphash()` | 0.080 [0.000, 0.228] | 0.001 | 0.071 [0.000, 0.198] | 0.023 % [0.000, 0.058] | - | 1.0 |
| YARA v2, other-family negatives (oracle) | 0.105 [0.008, 0.290] | 0.010 | 0.097 [0.008, 0.262] | 0.079 % [0.006, 0.229] | - | 1.0 |
| YARA v2, packaged prevalence, predicted family excluded (shipped) | 0.137 [0.025, 0.309] | 0.033 | 0.126 [0.023, 0.275] | 0.182 % [0.026, 0.447] | - | 1.0 |
| YARA v2, packaged prevalence, no exclusion (default install) | 0.084 [0.004, 0.230] | 0.010 | 0.073 [0.002, 0.200] | 0.082 % [0.012, 0.199] | - | 1.0 |

Benign FPR: share of the 32,671 benign Quo Vadis Speakeasy reports on which any rule of a run fires (mean over runs); the interval is Wilson on the reports hit by *any* run of the row, an upper bound for a single run (all runs share the same benign reports, so their counts cannot be pooled). Only 5,376 of these reports contain an event a Sigma rule here can match (5,651 file writes, 55 process creations, 0 registry value writes in total): the emulator records far fewer host actions than a sandbox, so this is a weak lower bound, not a benign-FPR estimate for sandbox traces. Predicted family: 5-fold cross-fitted FamilyModel (behaviour+static) on train; it matches the true family for 98.4 % of the reference runs.

Source: `results/rules_avast.json` (bench run [37109545948](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37109545948), commit `be11eac`).
<!-- /gen:rules -->

<img src="../figures/rule_generalisation.png" width="640" alt="Sibling recall against cross-family FPR (log scale) per synthesizer, with 95 % CIs">

What the ablation shows:

<!-- gen:rules-findings -->
- **Shipped configuration:** recall 0.293 [0.067, 0.560] (median family 0.090) at 0.006 % [0.003, 0.011] cross-family FPR; the oracle true-family exclusion gives 0.293 at 0.004 %.
- **Without a family model** (pip/Docker default) nothing is excluded, so rules that also match the sample's own family in the packaged corpus are dropped: recall 0.000 [0.000, 0.000].
- **False positives come down because of the real negative corpus:** with synthetic negatives only, the ladder reaches 9.32 % FPR; real negatives change FPR by -9.30 pp (family-level Wilcoxon p = 0.0078).
- **Recall comes from candidate generation, not the ladder or the negatives:** using every host action instead of technique-gated events adds +0.148 recall [-0.046, 0.398] (p = 0.25); the generalisation ladder adds only +0.004 [-0.003, 0.012] over exact values (p = 0.11).
- **Against the MVP**, the shipped synthesizer changes recall by +0.127 [-0.065, 0.378] (not significant at family level, p = 0.57) and FPR by -1.74 pp (p = 0.0078).
- **The mean hides the spread** (shipped, per family): Swisyn 0.998, Qakbot 0.937, Lokibot 0.417, njRAT 0.141, Zeus 0.090, Ursnif 0.029, Adload 0.020, Trickbot 0.005, Emotet 0.001. Emotet, Trickbot and Ursnif randomise every artefact that reduced reports record.

Source: `results/rules_avast.json` (bench run [37109545948](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37109545948), commit `be11eac`).
<!-- /gen:rules-findings -->

Family-clustered paired tests:

<!-- gen:rules-tests -->
| a | b | metric | b - a [95 % CI] | Wilcoxon p (9 families) | sign-flip p |
|---|---|---|---|---|---|
| Sigma MVP (technique-gated exact values, synthetic negatives) | ladder + 1,500 other-family negatives (true family excluded, oracle) | recall | +0.130 [-0.060, +0.382] | 0.5 | 0.36 |
| Sigma MVP (technique-gated exact values, synthetic negatives) | packaged corpus, predicted family excluded (shipped) | recall | +0.127 [-0.065, +0.378] | 0.57 | 0.4 |
| Sigma MVP (technique-gated exact values, synthetic negatives) | packaged corpus, predicted family excluded (shipped) | FPR | -1.737 pp [-2.746, -0.834] | 0.0078 | 0.0078 |
| Sigma MVP (technique-gated exact values, synthetic negatives) | every host action, exact values, synthetic negatives | recall | +0.148 [-0.046, +0.398] | 0.25 | 0.3 |
| every host action, exact values, synthetic negatives | ladder + synthetic negatives only | recall | +0.049 [+0.011, +0.091] | 0.0078 | 0.0078 |
| every host action, exact values + real negatives (oracle) | ladder + 1,500 other-family negatives (true family excluded, oracle) | recall | +0.004 [-0.003, +0.012] | 0.11 | 0.094 |
| every host action, exact values + real negatives (oracle) | ladder + 1,500 other-family negatives (true family excluded, oracle) | FPR | +0.007 pp [+0.001, +0.017] | 0.031 | 0.031 |
| ladder + synthetic negatives only | ladder + 1,500 other-family negatives (true family excluded, oracle) | recall | -0.066 [-0.121, -0.016] | 0.0078 | 0.0078 |
| ladder + synthetic negatives only | ladder + 1,500 other-family negatives (true family excluded, oracle) | FPR | -9.297 pp [-16.632, -3.812] | 0.0078 | 0.0078 |
| Sigma MVP (technique-gated exact values, synthetic negatives) | Sigma MVP + real negatives (oracle) | FPR | -1.743 pp [-2.752, -0.839] | 0.0078 | 0.0078 |
| packaged corpus, true family excluded (oracle) | packaged corpus, predicted family excluded (shipped) | recall | +0.000 [+0.000, +0.000] | 1 | 1 |
| packaged corpus, true family excluded (oracle) | packaged corpus, predicted family excluded (shipped) | FPR | +0.001 pp [-0.000, +0.006] | 1 | 1 |
| packaged corpus, predicted family excluded (shipped) | packaged corpus, no exclusion (default install, no family model) | recall | -0.293 [-0.557, -0.069] | 0.0039 | 0.0039 |
| packaged corpus, predicted family excluded (shipped) | packaged corpus, no exclusion (default install, no family model) | FPR | -0.005 pp [-0.010, -0.002] | 0.016 | 0.016 |
| ladder + 1,500 other-family negatives (true family excluded, oracle) | packaged corpus, predicted family excluded (shipped) | recall | -0.003 [-0.010, +0.001] | 0.56 | 0.38 |

Tests are on the family-mean differences (the 450 units are clustered within 9 families; with 9 families the smallest attainable two-sided p is 0.0039). Source: `results/rules_avast.json` (bench run [37109545948](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37109545948), commit `be11eac`).
<!-- /gen:rules-tests -->

## 4. Behavioural detection on MalbehavD-V1

Every sample goes through `api_sequence_to_trace`. Intervals over repeated splits and folds use the Nadeau-Bengio corrected resampled t.

<!-- gen:behaviour -->
| model | seed-0 holdout [bootstrap 95 %] | 5 x 70/30 (paper protocol) | 5x5-fold CV | 5 x 70/30, duplicate-free |
|---|---|---|---|---|
| MVP scorer (synthetic-trained, ATT&CK features) | 0.503 [0.468, 0.537] | 0.502 [0.499, 0.504] | 0.501 [0.499, 0.503] |  |
| same 9 ATT&CK features, retrained | 0.754 [0.722, 0.786] | 0.723 [0.673, 0.774] | 0.715 [0.695, 0.735] | 0.723 [0.705, 0.741] |
| **API uni+bigram tokens + LR (shipped scorer)** | 0.968 [0.955, 0.979] | 0.963 [0.951, 0.974] | 0.962 [0.952, 0.972] | 0.934 [0.908, 0.960] |
| API uni+bigram tokens + LightGBM | 0.966 [0.952, 0.978] | 0.961 [0.945, 0.978] | 0.963 [0.955, 0.971] | 0.939 [0.927, 0.950] |
| *MalDetConv CNN-BiGRU (Maniriho et al. 2022)* (arXiv:2209.03547v1, Table 3 (p. 19) and Table 5 (p. 19)) | *0.961* |  |  |  |
| *MalDy TF-IDF + XGBoost (as reported there)* (arXiv:2209.03547v1, Table 7 (p. 21)) | *0.9559* |  |  |  |

- Duplicates: 1,601 distinct sequences in 2,570 rows; 42.4 [38.4, 46.4] % of test rows have an exact copy in train. The LR is 99.5 [96.2, 100.0] % accurate on those and 93.9 [91.5, 96.3] % on unseen rows.
- Simulated shipped routing (per-split LR for traces with at least 5 calls, MVP scorer otherwise; p >= 0.5 counts as not benign): accuracy 0.960 [0.947, 0.972]; at the report's 'malicious' cut-off (p >= 0.8) 88.9 [85.6, 92.3] % of malicious traces are labelled malicious. 24.3 % of traces have fewer than 20 calls.
- Intervals: Nadeau-Bengio corrected t over repeated splits/folds (logit scale near 0/1). Source: `results/behaviour_malbehavd.json` (bench run [37093305708](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37093305708), commit `a575df4`).
<!-- /gen:behaviour -->

The MVP's synthetic-trained scorer does not transfer: API-only traces trigger almost no ATT&CK-mapped features.

## 5. Paper reproductions: paper vs reproduction vs SPECIMEN

**MalDetConv (Maniriho et al. 2022) on MalbehavD-V1** (`benchmarks/repro_maldetconv.py`). Page numbers refer to arXiv:2209.03547v1. Stated in the paper and used: embedding output dimension 100 (p. 15 and Fig. 10 A-2, p. 17); Conv1D 128 filters of size 8 with ReLU and dropout 0.2, max pooling, Conv1D 64 filters of size 5, max pooling, BiGRU with 120 units, flatten, dense 150/100/60 with ReLU and dropout 0.2, dense 15, sigmoid output (Fig. 10 A-2, p. 17); Adam with learning rate 0.001 and binary cross-entropy (p. 16); random 70/30 split (section 5.2, p. 18); Table 3 on p. 19. Not stated, so Keras defaults or guesses: pool size 2 and `valid` padding, batch size 32, 20 epochs, Keras tokenizer and `pad_sequences` defaults. The round-3 run had wrongly treated the layer sizes as unstated (they are in the Fig. 10 image); its guessed architecture is kept as an ablation. The duplicate-free protocol keeps one row per distinct *model input* (the last n calls) and drops inputs seen with both labels.

<!-- gen:maldetconv -->
| n calls | paper (arXiv:2209.03547v1, Table 3, p. 19) | reproduction, Fig. 10 architecture | reproduction, round-3 guess (ablation) | SPECIMEN LR | LR - reproduction (corrected paired t) | reproduction, duplicate-free inputs | SPECIMEN LR, duplicate-free inputs |
|---|---|---|---|---|---|---|---|
| 20 | 0.938 | 0.922 [0.916, 0.928] | 0.911 [0.889, 0.933] | 0.944 [0.937, 0.952] | +0.022, p = 2.1e-04 | 0.865 [0.848, 0.881] | 0.916 [0.903, 0.929] |
| 40 | 0.940 | 0.935 [0.925, 0.945] | 0.918 [0.899, 0.937] | 0.953 [0.943, 0.964] | +0.018, p = 0.014 | 0.899 [0.880, 0.918] | 0.929 [0.911, 0.946] |
| 60 | 0.952 | 0.944 [0.931, 0.958] | 0.922 [0.902, 0.942] | 0.958 [0.948, 0.969] | +0.014, p = 0.018 | 0.898 [0.869, 0.927] | 0.941 [0.927, 0.955] |
| 80 | 0.955 | 0.943 [0.933, 0.953] | 0.921 [0.904, 0.938] | 0.959 [0.948, 0.970] | +0.016, p = 0.012 | 0.923 [0.904, 0.942] | 0.940 [0.923, 0.957] |
| 100 | 0.961 | 0.950 [0.934, 0.966] | 0.923 [0.908, 0.938] | 0.957 [0.949, 0.966] | +0.008, p = 0.15 | 0.912 [0.882, 0.943] | 0.939 [0.924, 0.953] |

10 seeds x random 70/30; 20 epochs (not stated in the paper). Source: `results/repro_maldetconv.json` (bench run [37093305708](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37093305708), commit `a575df4`).
<!-- /gen:maldetconv -->

**Li et al. 2024 on Mal-API-2019** (`results/api_cross.json`). Table I (p. 6) has TF-IDF rows (RF, XGBoost, KNN, a 4-layer neural network) and TF-IDF + PCA rows; both are reproduced on their own features. SPECIMEN's LR also runs on the paper's unigram TF-IDF, and a random forest on SPECIMEN's uni+bigram TF-IDF, on identical folds, so each tested pair differs only in the model.

<!-- gen:li2024 -->
| model, features | paper (Table I, p. 6) | reproduction, all rows (5 seeds x 5-fold) | reproduction, duplicate-free |
|---|---|---|---|
| Random Forest, TF-IDF | 0.68 | 0.658 [0.649, 0.666] | 0.626 [0.614, 0.639] |
| XGBoost, TF-IDF | 0.68 | 0.653 [0.643, 0.662] | 0.618 [0.604, 0.632] |
| KNN, TF-IDF | 0.54 | 0.566 [0.554, 0.578] | 0.534 [0.523, 0.545] |
| NN, 4 hidden layers, TF-IDF | 0.56 | 0.613 [0.600, 0.626] | 0.586 [0.570, 0.603] |
| KNN, TF-IDF + PCA (SVD 100) | 0.54 | 0.570 [0.558, 0.582] | 0.536 [0.524, 0.548] |
| Random Forest, TF-IDF + PCA (SVD 100) | 0.62 | 0.639 [0.631, 0.648] | 0.607 [0.592, 0.622] |
| XGBoost, TF-IDF + PCA (SVD 100) | 0.62 | 0.634 [0.622, 0.646] | 0.604 [0.588, 0.620] |
| **SPECIMEN LR, TF-IDF** | - | 0.565 [0.554, 0.576] | 0.538 [0.522, 0.555] |
| **SPECIMEN LR, TF-IDF + PCA (SVD 100)** | - | 0.542 [0.530, 0.553] | 0.516 [0.501, 0.531] |
| **SPECIMEN LR, uni+bigram TF-IDF** | - | 0.667 [0.659, 0.674] | 0.638 [0.627, 0.650] |
| Random Forest, uni+bigram TF-IDF | - | 0.662 [0.649, 0.674] | 0.633 [0.619, 0.646] |

Feature-matched comparisons on identical folds (all rows; Nadeau-Bengio corrected paired t):

| a | b | b - a [95 % CI] | p |
|---|---|---|---|
| random-forest / tfidf | specimen-lr / tfidf | -0.093 [-0.105, -0.081] | 3.1e-14 |
| xgboost / tfidf | specimen-lr / tfidf | -0.088 [-0.099, -0.076] | 6.8e-14 |
| random-forest / tfidf+pca | specimen-lr / tfidf+pca | -0.098 [-0.111, -0.084] | 8.9e-14 |
| random-forest / uni+bigram | specimen-lr / uni+bigram | +0.005 [-0.008, +0.018] | 0.43 |
| specimen-lr / tfidf | specimen-lr / uni+bigram | +0.102 [+0.090, +0.113] | 2.2e-15 |

No grid search was run: the paper grid-searches (section 5.1, p. 6) but does not give the ranges, so defaults are used; part of any gap to the paper may come from that. Source: `results/api_cross.json` (bench run [37109548412](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37109548412), commit `be11eac`).
<!-- /gen:li2024 -->

**Cross-dataset.** The shipped MalbehavD-trained scorer, applied unchanged to Mal-API-2019 (all malware):

<!-- gen:cross -->
| Mal-API-2019 input | threshold | flagged [Wilson 95 %] |
|---|---|---|
| first 100 calls | 0.5 | 68.7 % [67.6, 69.7] |
| first 100 calls | 0.8 | 37.2 % [36.1, 38.4] |
| first 1,000 calls | 0.5 | 71.2 % [70.2, 72.3] |
| first 1,000 calls | 0.8 | 38.4 % [37.3, 39.5] |
| whole sequence | 0.5 | 71.6 % [70.5, 72.6] |
| whole sequence | 0.8 | 40.1 % [38.9, 41.2] |

Within Oliveira (integer-coded calls, duplicate-free, 5-fold x seeds, class-balanced LR): balanced accuracy 0.916 [0.896, 0.937], ROC AUC 0.982 [0.977, 0.987]. Source: `results/api_cross.json` (bench run [37109548412](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37109548412), commit `be11eac`).
<!-- /gen:cross -->

Cross-dataset transfer to Oliveira is not possible because the re-host has no API-name table.
