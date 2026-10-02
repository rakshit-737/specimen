# Limitations & roadmap

## Limitations

- **No live detonation.** The detonation controller (QEMU/KVM snapshot and revert, egress verification) and live eBPF capture are not built: they need an isolated lab host and must never run on this development machine. SPECIMEN replays recorded runs instead ([ADR 0001](adr/0001-report-replay-instead-of-live-detonation.md)). Recorded Sysmon exports are supported offline; binary `.evtx` must be exported to XML first.
- **Reduced reports have no timing.** Events from them are ordered deterministically and flagged `synthetic_ts`.
- **Negatives for rule specificity** are other malware families (a packaged sample of Avast-CTU training runs) plus a small synthetic benign set. Benign false-positive rates are unmeasured; the corpora searched and why none was adopted are listed on [Datasets](datasets.md#benign-behaviour-corpora-searched-round-3).
- **The EMBER LightGBM gate is standalone** (`triage-ember` on EMBER raw features). `analyze` has no PE-to-EMBER feature extractor and still detonates every PE.
- **Under temporal drift the gate is weaker**: AUC 0.989 and TPR 0.49 at 0.1 % FPR on Nov-Dec 2018 when trained on Jan-Sep (vs 0.997 / 0.85 on a random split). Detonations saved depend on the malware share of submissions.
- **Family attribution is closed-set over 10 families**; an abstain threshold marks low-probability reports as `unknown (closest: X)`, but it has not been evaluated on held-out families.
- **MalbehavD-V1 contains exact duplicate sequences** (1,601 distinct of 2,570); random splits, including the published ones, partly measure memorisation. The duplicate-free accuracy is 93.4 %.
- **The API behaviour scorer is trained on MalbehavD-V1** (Cuckoo API names, 2,570 samples). It only runs on traces with a real call sequence; reduced reports (no call logs) still use the MVP scorer, which is known to transfer poorly (see Benchmarks).
- No adversarial robustness evaluation of any model.

## Roadmap

- [x] Static gate wired into reconstruction on pre-captured logs (CAPE adapters, 49k real runs)
- [x] Detection synthesizer with measured generalisation
- [x] Unified report with evidence manifest; batch queue
- [x] Family attribution; job queue
- [x] Real-data behaviour scorer in the pipeline (API n-grams, pure-Python inference)
- [x] Emitted rules validated with pySigma and yara-python in CI
- [x] Sysmon (XML / JSON lines) to trace adapter
- [x] Seeds and confidence intervals for the static and behaviour benchmarks
- [ ] Stage 4: detonation controller with EICAR and benign binaries only, fail-closed without verified egress isolation (needs a lab hypervisor)
- [ ] Live eBPF capture (needs a Linux lab host)
- [x] Temporal EMBER evaluation on the full 2018 set (GitHub Actions)
- [x] Seeded rule benchmark with ablation; family variant chosen on a validation slice
- [x] More API-call datasets (Mal-API-2019, Oliveira) and paper reproductions (MalDetConv, Li et al. 2024)
- [ ] Benign behaviour corpus for Sigma FP measurement (Quo Vadis Speakeasy adapter)
- [ ] PE-to-EMBER feature extraction so `analyze` uses the trained gate
- [ ] Adversarial robustness checks
