# Benchmarks

All numbers come from `benchmarks/*.py` runs on the public datasets; the raw outputs are committed in [`results/`](https://github.com/rakshit-737/specimen/tree/main/results). Intervals are 95 %: bootstrap percentile intervals over test rows (1,000 resamples; 300 for EMBER AUC), t-intervals of the mean over seeds/folds, or binomial intervals for a single fixed split, as labelled.

## 1. Static gate on EMBER 2018 (`results/static_ember.json`)

Held-out stratified 25 % of 56,893 labelled rows; the gate threshold is tuned on a separate validation slice for 99 % malware recall.

| model | ROC AUC (95 % bootstrap CI) | TPR @ 0.1 % FPR | TPR @ 1 % FPR | accuracy | F1 |
|---|---|---|---|---|---|
| MVP heuristic (ported) | 0.560 [0.551, 0.568] | 0.007 | 0.017 | 0.523 | 0.488 |
| logistic regression | 0.968 [0.965, 0.971] | 0.010 | 0.574 | 0.926 | 0.930 |
| **LightGBM (SPECIMEN)** | **0.994 [0.993, 0.995]** | **0.839** | **0.924** | **0.965** | **0.967** |
| *EMBER paper, LightGBM, 2017 test set* | *0.9991* | *0.930* | *0.982* | | |

| gate policy @ 99 % recall | detonations saved | benign skipped | malware missed |
|---|---|---|---|
| MVP: detonate every PE | 0 % | 0 % | 0 % |
| MVP heuristic | 0 % | 0 % | 0 % |
| logistic regression | 17.4 % | 35.5 % | 1.0 % |
| **LightGBM, seed 0** | **42.3 %** | **87.8 %** | **1.2 %** |
| **LightGBM, 5 re-split seeds (mean ± 95 % CI)** | **42.2 ± 1.7 %** | **87.5 ± 3.1 %** | **1.16 ± 0.46 %** |

Across 5 seeds the LightGBM AUC is 0.9947 ± 0.0005. The miss rate at the "99 % recall" threshold varies between 0.6 % and 1.6 % because the threshold is set on a small validation slice.

![ROC curves of the three static gates](figures/static_roc.png)

*Caveats:* the archive prefix covers one month (2018-01), so the split is random rather than temporal and optimistic about drift; the model is trained on ~38k rows instead of 600k.

## 2. Family attribution on Avast-CTU CAPEv2 (`results/family_avast.json`)

The dataset authors' temporal split: 37,512 reports dated before 2019-08-01 for training, 11,464 later reports for testing. A single fixed split, so the interval is a binomial 95 % CI on accuracy.

| model | test accuracy (95 % CI) | macro-F1 |
|---|---|---|
| MVP Jaccard over ATT&CK technique sets | 0.878 [0.872, 0.884] | 0.713 |
| static.pe tokens only | 0.691 [0.682, 0.699] | 0.737 |
| behaviour + static tokens | 0.950 [0.946, 0.954] | 0.923 |
| **behaviour tokens only (SPECIMEN)** | **0.959 [0.955, 0.962]** | **0.926** |
| *HMIL on reduced reports (Bošanský et al.)* | *0.945* | |

![Family confusion matrix](figures/family_confusion.png)

## 3. Do auto-rules from one run generalise? (`results/rules_avast.json`)

10 reference runs per family from the training split; rules synthesized from each single run are applied to the later test split.

| synthesizer | mean sibling recall | mean cross-family FPR | runs with any sibling hit | rules / run |
|---|---|---|---|---|
| Sigma, MVP | 0.182 | 2.27 % | 51 % | 0.7 |
| **Sigma v2 (ladder + negative check)** | **0.327** | **0.016 %** | **79 %** | 6.0 |
| Sigma v2, 5 runs pooled | 0.416 | 0.065 % | 100 % | 29.6 |
| YARA `pe.imphash()` | 0.087 | 0.021 % | 23 % | 1.0 |
| YARA v2 (imphash or rare imports) | 0.083 | 0.002 % | 17 % | 0.9 |

![Rule generalisation](figures/rule_generalisation.png)

Every Sigma and YARA rule the pipeline emits on the bundled fixtures is parsed and converted by pySigma and compiled by yara-python in CI (`tests/test_rule_validation.py`).

## 4. Behavioural detection on MalbehavD-V1 (`results/behaviour_malbehavd.json`)

Every sample goes through `api_sequence_to_trace`. Seed-0 70/30 holdout (as in the dataset paper) with bootstrap CIs, then 5 re-split seeds, then 5-fold CV repeated over 5 seeds (25 folds).

| model | holdout accuracy (95 % CI) | holdout AUC (95 % CI) | 5 seeds x 70/30 accuracy | 5 x 5-fold CV accuracy |
|---|---|---|---|---|
| MVP scorer (synthetic-trained, ATT&CK features) | 0.503 [0.468, 0.537] | 0.228 [0.195, 0.259] | 0.502 ± 0.001 | 0.501 ± 0.001 |
| same 9 ATT&CK features, retrained | 0.754 [0.722, 0.786] | 0.779 [0.749, 0.811] | 0.724 ± 0.028 | 0.715 ± 0.008 |
| **API uni+bigram TF-IDF + LR (shipped scorer)** | **0.968 [0.955, 0.979]** | **0.991 [0.984, 0.996]** | **0.963 ± 0.006** | **0.962 ± 0.004** |
| API uni+bigram TF-IDF + LightGBM | 0.966 [0.952, 0.978] | 0.990 [0.983, 0.996] | 0.961 ± 0.009 | 0.963 ± 0.003 |
| *MalDetConv CNN-BiGRU (published)* | *0.961* | | | |
| *MalDy TF-IDF + XGBoost (as reported there)* | *0.956* | | | |

The seed-0 holdout sits at the upper end of the seed spread; the fairer headline is **~96.2-96.3 %**, on par with (not clearly above) the published deep models, whose single-split numbers fall inside our intervals. The LR model is exported to JSON and evaluated in pure Python inside the pipeline (max deviation from scikit-learn: 2e-16).
