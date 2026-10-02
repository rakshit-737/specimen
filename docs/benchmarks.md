# Evaluation

## Methodology

- Every number comes from a script in `benchmarks/` and a JSON file in [`results/`](https://github.com/rakshit-737/specimen/tree/main/results); see [Reproduce](reproduce.md).
- **Splits:** Avast-CTU uses the authors' temporal split (train before 2019-08-01). EMBER uses a temporal split (train Jan-Sep 2018, calibrate Oct, test Nov-Dec) plus the earlier one-month random split. MalbehavD uses the paper's random 70/30 split and a duplicate-free split.
- **Leakage controls:** exact-duplicate analysis (MalbehavD, Mal-API), "novel behaviour" test subsets (Avast-CTU), and model selection on a validation slice rather than on test.
- **Intervals (95 %):** percentile bootstrap over test rows for single holdouts; Nadeau-Bengio corrected resampled t over repeated splits and folds; Wilson for proportions; a two-level bootstrap (families, units) for rule recall; min-max over 5 seeds for the temporal EMBER runs.
- **Negative results are kept:** the MVP scorers, the over-general ladder with synthetic negatives, the closed-set family leak, and drift on EMBER.

## 1. Static gate on EMBER

The gate evaluated here is the standalone `triage-ember` model on EMBER raw features; `analyze` does not call it (see Architecture).

**Temporal (round 3, `results/static_ember_temporal.json`, `figures/static_temporal.png`).** Full EMBER-2018 archive downloaded in a GitHub Actions job (pinned SHA-256), vectorised with SPECIMEN's own featuriser, month-stratified subsample; train Jan-Sep, threshold calibrated for 99 % recall on October, test Nov-Dec; 5 subsample seeds (min-max shown).

| protocol | ROC AUC | TPR @ 0.1 % FPR | TPR @ 1 % FPR | detonations saved | malware missed | benign skipped |
|---|---|---|---|---|---|---|
| **temporal (SPECIMEN)** | **0.9892** (0.9889-0.9894) | **0.488** (0.466-0.538) | **0.873** (0.869-0.879) | 36.4 % | 0.63 % | 72.2 % |
| random split, same months and volume | 0.9965 | 0.852 | 0.949 | | | |
| *upstream EMBER-2018 LightGBM (600k train rows)* | *0.99643* | *0.868* | *0.965* | | | |

<img src="figures/static_temporal.png" width="480" alt="Per-month AUC and detonations saved on the temporal EMBER test months">

Under drift the gate is clearly worse than on a random split, mostly in the low-FPR region. "Detonations saved" depends on the malware share of the submissions: it is benign share x 72 % + malware share x 0.6 %, so about 8 % at a 90 % malware mix and 58 % at 20 %.

**Earlier one-month random split (`results/static_ember.json`).** A stratified 25 % of a 56,893-row prefix (2018-01 only), kept for comparison; this is optimistic about drift.

| model | ROC AUC | TPR @ 0.1 % FPR | TPR @ 1 % FPR | accuracy | F1 |
|---|---|---|---|---|---|
| MVP heuristic (ported) | 0.560 | 0.007 | 0.017 | 0.523 | 0.488 |
| logistic regression | 0.968 | 0.010 | 0.574 | 0.926 | 0.930 |
| LightGBM (SPECIMEN) | 0.994 | 0.839 (about 7 of 6,756 benign rows define this FPR) | 0.924 | 0.965 | 0.967 |

<img src="figures/static_roc.png" width="420" alt="ROC curves of the three static gates on EMBER">

Every gate decision carries TreeSHAP contributions over named features, for example `section.n_rx`, `datadir[2].size` or `imports:CreateToolhelp32Snapshot`. The hand-weighted MVP heuristic is barely better than chance on real PEs.

## 2. Family attribution on Avast-CTU CAPEv2: `results/family_avast.json`

Authors' temporal split: 37,512 training reports before 2019-08-01, 11,464 later test reports. 59 % of test reports have a behaviour-token set never seen in training ("novel"). Wilson 95 % CIs. The shipped variant is now chosen on a validation slice (training runs from 2019-06 on), not on test accuracy.

| model | test accuracy [95 % CI] | novel-behaviour accuracy | macro-F1 |
|---|---|---|---|
| MVP Jaccard over ATT&CK technique sets | 0.878 [0.872, 0.884] | 0.813 | 0.713 |
| static.pe tokens only | 0.700 [0.692, 0.709] | 0.504 | 0.744 |
| **behaviour + static tokens (shipped; best on validation, 0.987)** | **0.950 [0.946, 0.954]** | **0.925** | **0.923** |
| behaviour tokens only | 0.959 [0.955, 0.962] | 0.934 | 0.926 |
| *HMIL behaviour+static (Bošanský et al. 2022)* | *0.945* | | |
| *HMIL static-only* | *~0.63* | | |

<img src="figures/family_confusion.png" width="440" alt="Confusion matrix of the family model on the temporal test split">

The like-for-like comparison with HMIL is behaviour+static: 0.950 against 0.945. On test, behaviour-only is significantly better (McNemar, 159 vs 56 discordant reports, p = 1e-12), but picking it would mean selecting on the test set, so the published shipped number is the lower one. Each prediction lists the tokens that drove it.

**Open set.** In a leave-one-family-out run, the top probability for a held-out family's reports has a median of 0.45-0.79. The shipped abstain threshold is 0.6: known-family coverage 95.9 % at 98.2 % accuracy, but 30 % of unseen-family reports are still forced into a known family. Below the threshold, reports say `unknown (closest: X)`.

## 3. Do auto-rules from ONE run generalise? `results/rules_avast.json`

For each family and seed (5 seeds), 10 reference runs are drawn from the training split, rules are synthesised from each single run, and they are applied to the later test split. *Sibling recall* is the share of same-family test runs on which any rule fires. *Cross-family FPR* is the same share over other-family test runs. CIs come from a two-level bootstrap over families and units; paired Wilcoxon tests are over the 450 (seed, family, run) units. Per-unit values are in `results/rules_avast_units.csv`.

| synthesizer (ablation) | mean recall [95 % CI] | median family | novel-behaviour recall | cross-family FPR [95 % CI] | rules / run |
|---|---|---|---|---|---|
| Sigma MVP (exact values, synthetic negatives) | 0.174 [0.03, 0.40] | 0.005 | 0.193 | 1.85 % [0.91, 2.89] | 0.6 |
| Sigma MVP + real negatives | 0.000 | 0.000 | 0.000 | 0 % | 0.01 |
| exact values (rung 0) + real negatives | 0.298 [0.07, 0.56] | 0.056 | 0.291 | 0.009 % | 5.7 |
| ladder + synthetic negatives only | 0.372 [0.15, 0.62] | 0.228 | 0.392 | 8.67 % [3.65, 14.8] | 6.2 |
| ladder + real negatives (v2) | 0.304 [0.07, 0.58] | 0.057 | 0.298 | 0.020 % [0.002, 0.043] | 5.7 |
| ladder + real negatives, at most 3 rules | 0.227 [0.04, 0.46] | 0.045 | 0.215 | 0.007 % | 2.6 |
| **shipped (packaged negative corpus)** | **0.303 [0.08, 0.57]** | **0.058** | **0.296** | **0.004 %** [0.001, 0.007] | 5.7 |
| v2, 5 runs pooled | 0.391 [0.16, 0.64] | 0.265 | 0.350 | 0.056 % | 6.0 per 5-run pool |
| YARA `pe.imphash()` | 0.081 | 0.000 | 0.073 | 0.025 % | 1.0 |
| YARA v2 (imphash or rare imports) | 0.104 | 0.018 | 0.097 | 0.071 % | 0.9 |

<img src="figures/rule_generalisation.png" width="520" alt="Sibling recall against cross-family FPR (log scale) per synthesizer, with 95 % CIs">

What the ablation shows, compared with the round-2 claim ("roughly doubles recall, 140x fewer FPs"):

- **The real negative corpus does most of the work on false positives.** With only synthetic negatives the ladder over-generalises (8.7 % FPR). Given the same real negatives, the MVP's exact-value rules almost never survive, so most of the MVP-vs-v2 gap comes from the negatives, not the ladder.
- **The ladder adds little over exact values once real negatives are used**: +0.006 recall (Wilcoxon p = 7e-7) at about twice the FPR. That is a much smaller effect than the round-2 headline implied.
- **The mean hides the spread.** Per family (shipped): Swisyn 0.998, Qakbot 0.93, Lokibot 0.42, njRAT 0.24, Zeus 0.06, Adload 0.04 (n = 5, not estimable), Ursnif 0.02, Trickbot 0.004 and Emotet 0.001. Emotet, Trickbot and Ursnif randomise every artefact that reduced reports record. On Zeus, v2 is worse than the MVP (0.06 vs 0.31).
- The round-2 single-draw numbers (0.327 recall at 0.016 % FPR) were slightly optimistic; the seeded re-run gives 0.304 at 0.020 % for the same configuration.

## 4. Behavioural detection on MalbehavD-V1: `results/behaviour_malbehavd.json`

Every sample goes through `api_sequence_to_trace`. Intervals over repeated splits and folds use the Nadeau-Bengio corrected resampled t (they were naive t-intervals before round 3 and are now about 1.8-2.7x wider).

| model | seed-0 holdout [bootstrap CI] | 5 x 70/30 (paper protocol) | 5x5-fold CV | 5 x 70/30, duplicate-free |
|---|---|---|---|---|
| MVP scorer (synthetic-trained, ATT&CK features) | 0.503 [0.468, 0.537] | 0.502 ± 0.002 | 0.501 ± 0.002 | |
| same 9 ATT&CK features, retrained | 0.754 [0.722, 0.786] | 0.724 ± 0.050 | 0.715 ± 0.020 | 0.723 ± 0.018 |
| **API uni+bigram tokens + LR (shipped scorer)** | **0.968 [0.955, 0.979]** | **0.963 ± 0.011** | **0.962 ± 0.010** | **0.934 ± 0.026** |
| API uni+bigram tokens + LightGBM | 0.966 [0.952, 0.978] | 0.961 ± 0.016 | 0.963 ± 0.008 | 0.939 ± 0.012 |
| *MalDetConv CNN-BiGRU (published, random split)* | *0.961* | | | |
| *MalDy TF-IDF + XGBoost (as reported there)* | *0.956* | | | |

**Duplicate leakage.** The 2,570 rows hold only 1,601 distinct sequences (478 distinct malicious ones); 42 ± 4 % of test rows in a random 70/30 split have an exact copy in train. The LR is 99.5 % accurate on those and 93.9 % on unseen rows. The paper protocol (and the published numbers) therefore include memorised duplicates; the duplicate-free number is the honest one.

**Pipeline path.** The shipped routing now sends traces with at least 5 API calls to the LR (it used to need 20, which sent 24 % of MalbehavD traces to the MVP scorer at 56 % accuracy). End-to-end accuracy through `behaviour_score` is 0.960 ± 0.013. The shipped JSON model deviates from a scikit-learn refit by at most 1.3e-6 (5-decimal rounding).

The MVP's synthetic-trained scorer does not transfer at all: API-only traces trigger almost no ATT&CK-mapped features, so its ranking is inverted.

## 5. Paper reproductions: paper vs reproduction vs SPECIMEN

**MalDetConv (Maniriho et al. 2022) on MalbehavD-V1** (`results/repro_maldetconv.json`, `benchmarks/repro_maldetconv.py`). Re-implemented in PyTorch from the paper's text: embedding, 2x Conv1D+MaxPool, BiGRU, dense ReLU with dropout 0.2, sigmoid output; Keras-style pre-padding and truncation to n calls; random 70/30 split; 10 seeds. The paper gives the layer sizes only as an image, so the sizes used (64 filters, kernel 3, 64 GRU units, lr 1e-3, batch 32, 20 epochs) are guesses and are recorded in the file. SPECIMEN's LR is trained on the same truncated sequences and the same splits.

| n calls | paper (Table 3) | our reproduction | SPECIMEN LR | reproduction, duplicate-free | SPECIMEN LR, duplicate-free |
|---|---|---|---|---|---|
| 20 | 0.938 | 0.915 ± 0.018 | 0.944 ± 0.008 | 0.863 ± 0.017 | 0.919 ± 0.019 |
| 40 | 0.940 | 0.914 ± 0.035 | 0.953 ± 0.010 | 0.869 ± 0.020 | 0.933 ± 0.022 |
| 60 | 0.952 | 0.920 ± 0.021 | 0.958 ± 0.011 | 0.872 ± 0.024 | 0.939 ± 0.016 |
| 80 | 0.955 | 0.925 ± 0.016 | 0.959 ± 0.011 | 0.878 ± 0.038 | 0.940 ± 0.019 |
| 100 | 0.961 | 0.923 ± 0.016 | 0.957 ± 0.009 | 0.877 ± 0.028 | 0.938 ± 0.020 |

Our reproduction falls 2-4 points short of the paper. The likeliest cause is the unstated layer sizes and training schedule. On a duplicate-free split the CNN-BiGRU loses about 5 points while the n-gram LR loses about 2.

**Li et al. 2024 on Mal-API-2019** (`results/api_cross.json`). 8-class family classification, TF-IDF with 5-fold CV (the grid ranges and PCA size are not stated, so defaults are used):

| model | paper (Table I) | reproduction, all rows | reproduction, duplicate-free |
|---|---|---|---|
| Random Forest | 0.68 | 0.637 ± 0.008 | 0.605 ± 0.015 |
| XGBoost | 0.68 | 0.632 ± 0.015 | 0.602 ± 0.017 |
| KNN | 0.54 | 0.569 ± 0.014 | 0.535 ± 0.013 |
| MLP | 0.56 | 0.619 ± 0.015 | 0.590 ± 0.017 |
| **SPECIMEN uni+bigram LR** | - | **0.666 ± 0.010** | **0.639 ± 0.014** |

**Cross-dataset.** The shipped MalbehavD-trained scorer, applied unchanged to Mal-API-2019 (all malware), flags 71.6 % [70.5, 72.6] of sequences at p >= 0.5 but only 40.1 % at the "malicious" cut-off of 0.8, so it transfers only partly. Within Oliveira (integer-coded calls, duplicate-free, 5-fold), the n-gram LR reaches a balanced accuracy of 0.913 ± 0.025 and an AUC of 0.982. Cross-dataset transfer to Oliveira is not possible because the re-host has no API-name table.


