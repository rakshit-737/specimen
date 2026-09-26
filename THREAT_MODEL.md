# Threat Model: SPECIMEN (MVP)

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
| Trace spoofing (wrong sample) | `sample_sha256` binding is checked; the trace hash is recorded in the manifest | Signed traces from the sandbox |
| Evidence tampering | SHA-256 of sample, trace and report content in the manifest | Signed manifest, append-only store |
| Adversarial evasion (bland static features, sandbox-aware behavior) | The gate detonates every PE regardless of static score; behavior can override the static verdict | Sandbox-evasion detection, longer runs |
| Over-broad auto rules | YARA strings found in the benign corpus are excluded; Sigma rules that match benign traces are dropped | Larger benign corpus, real rule compilers |
| Model poisoning | The model is trained on a deterministic synthetic corpus and bundled | Provenance tracking for real training data |
| Markdown/Mermaid injection in reports | Labels are truncated and quotes stripped | Full escaping for HTML rendering |
