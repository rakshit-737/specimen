# Threat Model: SPECIMEN 1.1

## Assets
- The analyst workstation and host network
- The integrity of evidence (sample, trace, report)
- The quality of detections pushed downstream, where false positives cost SOC time

## Trust boundaries
1. **Sample bytes**: hostile. They are only read, capped at 50 MB, and scanned with regex. They are never executed, imported, unpacked or decompressed.
2. **Traces and sandbox reports** (native trace, CAPE/Cuckoo JSON, Sysmon XML/JSON lines, Speakeasy JSON): semi-trusted, because they are produced by a sandbox, emulator or lab host that the sample may have influenced. They are size-capped before parsing, schema-validated, coerced and capped per field, and bound to the sample's hash when they record one.
3. **Generated rules / report**: consumed by humans and SIEMs. Rules are marked `experimental` and must be reviewed before deployment; reports are strict JSON and entity-encoded Markdown.
4. **Model files**: downloaded release assets, checked against pinned SHA-256s (`scripts/model_assets.json`).

## Threats and mitigations

| Threat | Mitigation | Residual / TODO |
| --- | --- | --- |
| Accidental execution of a sample | No code path executes anything; the pipeline only reads bytes | A future detonation controller must run only in an isolated VM with no egress |
| Sandbox escape or egress during detonation | Out of scope: SPECIMEN only replays recorded runs | TODO: verify isolation, revert snapshots, block egress on the host firewall |
| Malformed or huge input (DoS) | Inputs above `SPECIMEN_MAX_INPUT_MB` (default 512) are refused before reading; native traces are capped at 100k events, Sysmon exports at 50 MB / 200k events; `NaN`, `Infinity` and out-of-range numbers are coerced or rejected; JSON nested deeply enough to exhaust the parser and malformed XML become one-line errors, never tracebacks | Streaming parsers for very large traces |
| Hostile sandbox report (CAPE/Cuckoo JSON) | The adapter coerces every value, truncates strings to 512 chars, caps lists (2,000 per kind, 5,000 calls per process), ignores unknown shapes and never `eval`s anything | Streaming JSON parsing |
| Malicious model artefact | Models are LightGBM text and `.npz` numeric arrays; no pickle/joblib is loaded anywhere; release assets are verified against pinned SHA-256s before the docs and release workflows use them | Signed model artefacts |
| Trace spoofing (trace of a different sample) | `analyze` refuses a trace whose recorded sample hash (native `sample_sha256`, CAPE `target.file.sha256`, Sysmon event 1 `Hashes` SHA256) differs from the sample's SHA-256. A trace that records no hash is replayed as `unbound`: the manifest says so and the verdict confidence is lowered to `low`. The trace hash is recorded in the manifest | Signed traces from the sandbox; Sysmon configs should hash process images (`HashAlgorithms`) |
| Evidence tampering | SHA-256 of sample, trace and report content in the manifest | Signed manifest, append-only store |
| Adversarial evasion (bland static features, sandbox-aware behaviour) | `analyze` replays every PE regardless of static score; behaviour can override the static verdict. The trained EMBER gate is standalone (`triage-ember`) and would skip PEs if wired in | Sandbox-evasion detection, longer runs |
| Over-broad auto rules | String YARA candidates found in the benign blobs are excluded. Sigma v2 keeps only the most general pattern with zero hits on the negative corpus (synthetic benign traces plus the packaged Avast-CTU corpus minus the predicted family) and at least 10 literal characters beyond generic prefixes (hive roots, `\Environment`, MuiCache, user profile folders). Measured false-positive rates: see the generated sentence below. Rules are compiled with pySigma and yara-python in CI (EscapedWildcardValidator, SQLite conversion) | Benign *sandbox* reports; without a family model nothing is left out of the corpus, which costs recall rather than precision |
| Model poisoning | Real-data models are trained only on pinned, SHA-256-verified public datasets with temporal splits for Avast-CTU and EMBER and random plus duplicate-free splits for MalbehavD | Label-noise audits; provenance for any future user-supplied training data |
| Markdown/Mermaid injection in reports | Every report-derived string in Markdown is HTML-escaped and has every Markdown-structural character (`[ ] ( ) ! \ | ` * _ # ~`) entity-encoded, so sandbox data cannot form links, images, code spans or table cells; the pymdown snippet marker `--8<--` is broken; URLs (including protocol-relative and integer/hex/octal IPv4 hosts) are defanged; Mermaid labels are neutralised; Sigma values go through a YAML-safe quoter and YARA strings through one escaper; hashes are validated. A test renders a canary report with Python-Markdown and asserts that no link, image, `href` or `src` comes from report data | Signed reports |

<!-- gen:threat-fpr -->
**Measured rule false positives** (`results/rules_avast.json`): with the shipped negative corpus (packaged corpus minus the predicted family) rules from one run fire on 0.006 % [0.003, 0.011] of later other-family sandbox reports and fire on 0.000 % [0.000, 0.012] of benign Speakeasy reports (an emulator lower bound: these reports contain few host actions). The oracle settings, which remove the true family from the negatives and are not what the product does, give 0.019 % [0.004, 0.039] (1,500 other-family runs) and 0.004 % [0.002, 0.007] (packaged corpus). Source: `results/rules_avast.json` (bench run [37109545948](https://github.com/rakshit-737/specimen-malware-analysis/actions/runs/37109545948), commit `be11eac`).
<!-- /gen:threat-fpr -->
