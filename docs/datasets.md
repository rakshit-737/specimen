# Datasets

Nothing is committed to git. `scripts/download_data.py` fetches the data into `$SPECIMEN_DATA` (outside the repo) with resumable range requests and records SHA-256 hashes in `SHA256SUMS` (`--verify` re-checks them). Only sandbox reports, pre-extracted features and API sequences are downloaded, never binaries.

| Dataset | What is used | Size | Licence | Citation |
|---|---|---|---|---|
| [Avast-CTU Public CAPEv2](https://github.com/avast/avast-ctu-cape-dataset) | Reduced reports (`behavior.summary` + `static.pe`) for 48,976 samples in 10 families, labels and dates | 593 MB zip | MIT (per `Licences.txt`) | Bošanský et al., *Avast-CTU Public CAPE Dataset*, arXiv:2209.03188 (2022) |
| [EMBER 2018 v2](https://github.com/elastic/ember) | Raw feature JSON lines. Locally a 120 MB prefix (56,893 rows, 2018-01); the full 1.7 GB archive (pinned SHA-256 `b6052eb8...7812`) is downloaded only inside the GitHub Actions `bench` workflow for the temporal evaluation | 1.7 GB | data: MIT | Anderson & Roth, *EMBER*, arXiv:1804.04637 (2018) |
| [Mal-API-2019](https://github.com/ocatak/malware_api_class) | 7,107 Cuckoo API-call sequences in 8 malware families (2.17 GB text, streamed line by line from the zip) | 12 MB zip | MIT | Catak et al., *PeerJ CS* 2020 |
| Oliveira API-call sequences (re-host of the 2019 Kaggle/IEEE DataPort release) | 42,797 malware + 1,079 goodware, first 100 calls, integer-coded | 15 MB | not stated by the re-host; used for within-dataset evaluation only | Oliveira, *Malware Analysis Datasets: API Call Sequences*, 2019 |
| [MalbehavD-V1](https://github.com/mpasco/MalbehavD-V1) | Cuckoo API-call sequences, 1,285 benign + 1,285 malicious | 2.3 MB | MIT | Maniriho et al., *MalDetConv*, arXiv:2209.03547 (2022); *API-MalDetect*, JNCA 2023 |

## Benign behaviour corpora searched (round 3)

Rule specificity needs benign *behaviour*, ideally CAPE/Cuckoo reports of clean software. What was checked:

| corpus | benign behaviour? | format | size | licence | decision |
|---|---|---|---|---|---|
| Avast-CTU CAPEv2 | no (malware only) | CAPE reduced reports | 48,976 | MIT | used as *other-family* negatives |
| MalbehavD-V1 | yes, 1,285 | API names only, no file/registry/process arguments | 2.3 MB | MIT | cannot exercise Sigma fields (no paths, keys or command lines) |
| Oliveira 2019 | yes, 1,079 | integer-coded API ids, no name table in the re-host | 15 MB | unclear | no arguments; not usable for Sigma |
| Mal-API-2019 | no (malware only) | API names | 2.2 GB | MIT | cross-dataset behaviour test only |
| KHAS API lists | n/a | static PE imports, not behaviour; CSVs truncated against the documented counts | small | none | excluded |
| [Quo Vadis Speakeasy](https://huggingface.co/datasets/dtrizna/quovadis-speakeasy) | yes, 24,434 + 7,944 clean reports | Speakeasy *emulation* reports (APIs, file access, network per entry point) | 5.2 GB | Apache-2.0 | best candidate; needs an emulator-to-trace adapter and an Actions run. Not done in this round: emulation reports differ from sandbox runs (no real registry state, partial process trees), so FPR on them would be a lower bound |

So the Sigma FPR reported is still *cross-family*, not benign. The shipped negative corpus (`specimen/data/negatives.json.gz`) holds event lines from a stratified sample of Avast-CTU *training* runs only.

## Committed fixtures

- `tests/fixtures/cape/`: four real Avast-CTU reduced reports trimmed to about 8 KB each, plus one clearly synthetic full-format CAPE report.
- `tests/fixtures/sysmon/lab_run.xml`: a synthetic Sysmon XML export (documentation IP ranges, `.invalid` domains).

## Citations

```
Bošanský B., Kouba D., Maňhal O., Sick T., Lisý V., Křoustek J., Somol P. Avast-CTU Public CAPE Dataset. arXiv:2209.03188, 2022.
Anderson H. S., Roth P. EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. arXiv:1804.04637, 2018.
Maniriho P., Mahmood A. N., Chowdhury M. J. M. MalDetConv / API-MalDetect. arXiv:2209.03547, 2022; JNCA 218, 2023.
```
