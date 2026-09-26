# Limitations & roadmap

## Limitations

- **No live detonation.** The detonation controller (QEMU/KVM snapshot and revert, egress verification) and live eBPF capture are not built: they need an isolated lab host and must never run on this development machine. SPECIMEN replays recorded runs instead ([ADR 0001](adr/0001-report-replay-instead-of-live-detonation.md)). Recorded Sysmon exports are supported offline; binary `.evtx` must be exported to XML first.
- **Reduced reports have no timing.** Events from them are ordered deterministically and flagged `synthetic_ts`.
- **Negatives for rule specificity** are other malware families plus a small synthetic benign set, not a large benign behaviour corpus. Real-world false-positive rates on clean enterprise telemetry are unmeasured (no public benign CAPE corpus of adequate size was found).
- **EMBER is evaluated on a one-month prefix** (random split, 5 seeds). A temporal evaluation needs the full 2018 set (~9 GB unpacked) and is left out on purpose to respect the per-project data budget.
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
- [ ] Benign CAPE corpus for Sigma FP measurement
- [ ] Temporal EMBER evaluation on the full 2018 set; adversarial robustness checks
