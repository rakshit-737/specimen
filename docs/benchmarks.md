# Evaluation

## Methodology

- **Traceability.** Every number comes from a script in `benchmarks/`, run by the GitHub Actions `bench` workflow, and a JSON file in [`results/`](https://github.com/rakshit-737/specimen/tree/main/results) whose `provenance` block names the run id, job, commit, command and runtime. The tables on this page and in the README are generated from those files by `scripts/render_results.py` (CI fails if they drift), and every value is rounded once, there. See [Reproduce](reproduce.md).
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
<!-- /gen:static-temporal -->

<img src="../figures/static_temporal.png" width="480" alt="Per-month TPR and detonations saved on the temporal EMBER test months">

The upstream reference is not like-for-like: it trains on all 600k labelled Jan-Oct rows with EMBER's own 2,381 features, while SPECIMEN uses a 132k-row Jan-Sep subsample, its own featuriser and keeps October for calibration. The gap therefore mixes training volume and features with drift. "Detonations saved" depends on the malware share of the submissions: benign share x benign skipped + malware share x malware missed.

**Earlier one-month random split.** A stratified 25 % of a 56,893-row prefix (2018-01 only); optimistic about drift.

<!-- gen:static-random -->
<!-- /gen:static-random -->

<img src="../figures/static_roc.png" width="420" alt="ROC curves of the three static gates on EMBER">

Every gate decision carries TreeSHAP contributions over named features, for example `section.n_rx`, `datadir[2].size` or `imports:CreateToolhelp32Snapshot`.

## 2. Family attribution on Avast-CTU CAPEv2

Authors' temporal split: 37,512 training reports before 2019-08-01, 11,464 later test reports. "Novel behaviour" = test reports whose behaviour-token set never occurs in training.

<!-- gen:family -->
<!-- /gen:family -->

<img src="../figures/family_confusion.png" width="440" alt="Confusion matrix of the family model on the temporal test split">

The like-for-like comparison with HMIL (Bošanský et al. 2022) is behaviour+static. Behaviour-only can score higher on test, but choosing it there would mean selecting on the test set, so the published shipped number is the validation-selected variant. Each prediction lists the tokens that drove it.

**Open set.** The abstain threshold is the largest value with at least 95 % known-family coverage on the validation slice (models fitted on earlier runs; leave-one-family-out on validation for unseen families), applied unchanged to test:

<!-- gen:family-openset -->
<!-- /gen:family-openset -->

## 3. Do auto-rules from ONE run generalise?

For each family and seed (5 seeds), 10 reference runs are drawn from the training split (never one of the 1,800 runs inside the packaged negative corpus), rules are synthesised from each single run, and they are applied to the later test split and to the 32,673 benign Speakeasy reports. *Sibling recall* is the share of same-family test runs on which any rule fires; *cross-family FPR* the same share over other-family test runs; *benign FPR* the share of benign reports. Per-run values are in `results/rules_avast_units.csv`.

Rows marked **oracle** remove the *true* family from the negatives, which the product cannot do. The **shipped** row is what `analyze` and `report` do with the released family model: they remove the family the model *predicts* (here from 5-fold cross-fitted models, so the prediction is out-of-sample). The **default install** row is the pip/Docker package without a family model: nothing is removed.

<!-- gen:rules -->
<!-- /gen:rules -->

<img src="../figures/rule_generalisation.png" width="640" alt="Sibling recall against cross-family FPR (log scale) per synthesizer, with 95 % CIs">

What the ablation shows:

<!-- gen:rules-findings -->
<!-- /gen:rules-findings -->

Family-clustered paired tests:

<!-- gen:rules-tests -->
<!-- /gen:rules-tests -->

## 4. Behavioural detection on MalbehavD-V1

Every sample goes through `api_sequence_to_trace`. Intervals over repeated splits and folds use the Nadeau-Bengio corrected resampled t.

<!-- gen:behaviour -->
<!-- /gen:behaviour -->

The MVP's synthetic-trained scorer does not transfer: API-only traces trigger almost no ATT&CK-mapped features.

## 5. Paper reproductions: paper vs reproduction vs SPECIMEN

**MalDetConv (Maniriho et al. 2022) on MalbehavD-V1** (`benchmarks/repro_maldetconv.py`). Page numbers refer to arXiv:2209.03547v1. Stated in the paper and used: embedding output dimension 100 (p. 15 and Fig. 10 A-2, p. 17); Conv1D 128 filters of size 8 with ReLU and dropout 0.2, max pooling, Conv1D 64 filters of size 5, max pooling, BiGRU with 120 units, flatten, dense 150/100/60 with ReLU and dropout 0.2, dense 15, sigmoid output (Fig. 10 A-2, p. 17); Adam with learning rate 0.001 and binary cross-entropy (p. 16); random 70/30 split (section 5.2, p. 18); Table 3 on p. 19. Not stated, so Keras defaults or guesses: pool size 2 and `valid` padding, batch size 32, 20 epochs, Keras tokenizer and `pad_sequences` defaults. The round-3 run had wrongly treated the layer sizes as unstated (they are in the Fig. 10 image); its guessed architecture is kept as an ablation. The duplicate-free protocol keeps one row per distinct *model input* (the last n calls) and drops inputs seen with both labels.

<!-- gen:maldetconv -->
<!-- /gen:maldetconv -->

**Li et al. 2024 on Mal-API-2019** (`results/api_cross.json`). Table I (p. 6) has TF-IDF rows (RF, XGBoost, KNN, a 4-layer neural network) and TF-IDF + PCA rows; both are reproduced on their own features. SPECIMEN's LR also runs on the paper's unigram TF-IDF, and a random forest on SPECIMEN's uni+bigram TF-IDF, on identical folds, so each tested pair differs only in the model.

<!-- gen:li2024 -->
<!-- /gen:li2024 -->

**Cross-dataset.** The shipped MalbehavD-trained scorer, applied unchanged to Mal-API-2019 (all malware):

<!-- gen:cross -->
<!-- /gen:cross -->

Cross-dataset transfer to Oliveira is not possible because the re-host has no API-name table.
