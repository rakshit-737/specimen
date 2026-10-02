# Threat Model: SPECIMEN (v0.2)

## Assets
- The analyst workstation and host network
- The integrity of evidence (sample, trace, report)
- The quality of detections pushed downstream, where false positives cost SOC time

## Trust boundaries
1. **Sample bytes**: hostile. They are only read, capped at 50 MB, and scanned with regex. They are never executed, imported, unpacked or decompressed.
2. **Trace JSON**: semi-trusted, because it is produced by a sandbox that may be compromised. The schema is validated, event types are allow-listed, and the event count is capped (100k).
3. **Generated rules / report**: consumed by humans and SIEMs. They are marked `experimental` and must be reviewed before deployment.

## Threats and mitigations

| Threat | Mitigation (MVP) | Residual / TODO |
| --- | --- | --- |
| Accidental execution of a sample | No code path executes anything; the pipeline only reads bytes | A future detonation controller must run only in an isolated VM with no egress |
| Sandbox escape or egress during detonation | Out of scope for the MVP, which only replays traces | TODO: verify isolation, revert snapshots, block egress on the host firewall |
| Malformed or huge trace (DoS) | JSON validation, event cap, typed `Event` validation | Streaming parser for very large traces |
| Hostile sandbox report (CAPE/Cuckoo JSON) | The adapter coerces every value, truncates strings to 512 chars, caps lists (2,000 per kind, 5,000 calls per process), ignores unknown shapes and never `eval`s anything. Inputs above `SPECIMEN_MAX_INPUT_MB` (default 512) are refused before reading | Streaming JSON parsing |
| Malicious model artefact | Models are LightGBM text and `.npz` numeric arrays; no pickle/joblib is loaded anywhere | Sign `models/` artefacts |
| Trace spoofing (wrong sample) | `sample_sha256` binding is checked; the trace hash is recorded in the manifest | Signed traces from the sandbox |
| Evidence tampering | SHA-256 of sample, trace and report content in the manifest | Signed manifest, append-only store |
| Adversarial evasion (bland static features, sandbox-aware behavior) | `analyze` detonates (replays) every PE regardless of static score; behavior can override the static verdict. The trained EMBER gate is standalone (`triage-ember`) and would skip PEs if wired in | Sandbox-evasion detection, longer runs |
| Over-broad auto rules | YARA strings found in the benign corpus are excluded. Sigma v2 keeps only the most general pattern with zero hits on a negative corpus and at least 10 literal characters. Measured cross-family FPR is 0.020 % [0.002, 0.043] (ladder + real negatives, seeded; results/rules_avast.json); 0.004 % is the oracle true-family-excluded setting. Rules are compiled with pySigma and yara-python in CI (EscapedWildcardValidator, SQLite conversion) | Real benign behaviour corpus (see docs/datasets.md) |
| Model poisoning | Real-data models are trained only on pinned, SHA-256-verified public datasets (scripts/download_data.py) with temporal splits for Avast-CTU and EMBER (temporal run) and random plus duplicate-free splits for MalbehavD | Label-noise audits; provenance for any future user-supplied training data |
| Markdown/Mermaid injection in reports | All report-derived strings are HTML-escaped, pipes/backticks/`--8<--` neutralised, IOCs defanged; Sigma values go through a YAML-safe quoter and YARA strings through one escaper; hashes are validated | Signed reports |
