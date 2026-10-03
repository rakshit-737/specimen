# Limitations & roadmap

## Limitations

- **No live detonation.** The detonation controller (QEMU/KVM snapshot and revert, egress verification) and live eBPF capture are not built: they need an isolated lab host and must never run on this development machine. SPECIMEN replays recorded runs instead ([ADR 0001](adr/0001-report-replay-instead-of-live-detonation.md)). Recorded Sysmon exports are supported offline; binary `.evtx` must be exported to XML first.
- **Reduced reports have no timing.** Events from them are ordered deterministically and flagged `synthetic_ts`.
- **Benign false positives are measured on emulation reports.** The benign Sigma FPR uses 32,673 benign Quo Vadis Speakeasy reports. Speakeasy emulates the binary instead of running it, so it records fewer host actions (and no real registry state or full process tree) than a CAPE sandbox: the benign FPR is a lower bound for sandbox traces. The cross-family FPR uses real CAPE reports of other malware families.
- **Rule quality depends on the family model.** The shipped synthesizer leaves the *predicted* family out of the packaged negative corpus. Without a family model (the default pip and Docker install) nothing is left out, and rules that also match the sample's own family are dropped, which costs recall ([Evaluation](benchmarks.md#3-do-auto-rules-from-one-run-generalise)).
- **The EMBER LightGBM gate is standalone** (`triage-ember` on EMBER raw features). `analyze` has no PE-to-EMBER feature extractor and still replays every PE.
- **Under temporal drift the gate is weaker** than on a random split, and it is trained on a 132k-row subsample with SPECIMEN's own features, so it is well below the upstream 600k-row EMBER model on the same months.
- **Family attribution is closed-set over 10 families**; some unseen-family reports still pass the abstain threshold, which is chosen on a validation slice ([Evaluation](benchmarks.md#2-family-attribution-on-avast-ctu-capev2)).
- **MalbehavD-V1 contains exact duplicate sequences** (1,601 distinct of 2,570); random splits, including the published ones, partly measure memorisation.
- **The API behaviour scorer is trained on MalbehavD-V1** (Cuckoo API names, 2,570 samples). It only runs on traces with a real call sequence; reduced reports (no call logs) still use the MVP scorer, which is known to transfer poorly.
- **Paper reproductions are re-implementations.** Settings the papers do not state (MalDetConv's epochs and batch size; Li et al.'s grid-search ranges, PCA size and network widths) are guessed and recorded in the result files; no grid search is run.
- No adversarial robustness evaluation of any model.

## Roadmap

- [x] Static gate wired into reconstruction on pre-captured logs (CAPE adapters, 49k real runs)
- [x] Detection synthesizer with measured generalisation, shared by `analyze` and `report`
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
