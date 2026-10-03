# Datasets

Nothing is committed to git. `scripts/download_data.py` fetches the data into `$SPECIMEN_DATA` (outside the repo) with resumable range requests and records SHA-256 hashes in `SHA256SUMS` (`--verify` re-checks them against the pinned values). Only sandbox reports, emulation reports, pre-extracted features and API sequences are downloaded, never binaries. Downloads over 1 GB run only inside the GitHub Actions `bench` workflow.

| Dataset | What is used | Size | Licence | Citation |
|---|---|---|---|---|
| [Avast-CTU Public CAPEv2](https://github.com/avast/avast-ctu-cape-dataset) | Reduced reports (`behavior.summary` + `static.pe`) for 48,976 samples in 10 families, labels and dates | 593 MB zip | MIT (per `Licences.txt`) | Bošanský et al. 2022 |
| [EMBER 2018 v2](https://github.com/elastic/ember) | Raw feature JSON lines. Locally a 120 MB prefix (56,893 rows, 2018-01); the whole 1.7 GB archive (pinned SHA-256 `b6052eb8...7812`, checked in full) only inside the `bench` workflow | 1.7 GB | MIT | Anderson & Roth 2018 |
| [Quo Vadis Speakeasy](https://huggingface.co/datasets/dtrizna/quovadis-speakeasy) | Benign emulation reports only: `report_clean` (24,434 train + 7,944 test) and `report_windows_syswow64` (236 + 59), 32,673 in total, at the pinned revision `fc2e98fa`; converted to a compact cache by `scripts/build_speakeasy_cache.py` inside the `bench` workflow | about 1.6 GB of JSON | Apache-2.0 | Trizna 2022 |
| [Mal-API-2019](https://github.com/ocatak/malware_api_class) | 7,107 Cuckoo API-call sequences in 8 malware families (2.17 GB text, streamed line by line from the zip) | 12 MB zip | MIT | Catak & Yazı 2019; Catak et al. 2020 |
| Oliveira API-call sequences (public re-host of the 2019 Kaggle / IEEE DataPort release) | 42,797 malware + 1,079 goodware, first 100 calls, integer-coded | 15 MB | not stated by the re-host; used for within-dataset evaluation only | Oliveira 2019 |
| [MalbehavD-V1](https://github.com/mpasco/MalbehavD-V1) | Cuckoo API-call sequences, 1,285 benign + 1,285 malicious | 2.3 MB | MIT | Maniriho et al. 2022 |

The Oliveira file is fetched from `github.com/Hellcake/malware-detection` (`dynamic_api_call_sequence_per_malware_100_0_306.csv`, SHA-256 pinned in `scripts/download_data.py`); the original release is on Kaggle and IEEE DataPort.

## Benign behaviour corpora searched

Rule specificity needs benign *behaviour*, ideally CAPE/Cuckoo reports of clean software. What was checked:

| corpus | benign behaviour? | format | size | licence | decision |
|---|---|---|---|---|---|
| Avast-CTU CAPEv2 | no (malware only) | CAPE reduced reports | 48,976 | MIT | used as *other-family* negatives and for the cross-family FPR |
| MalbehavD-V1 | yes, 1,285 | API names only, no file/registry/process arguments | 2.3 MB | MIT | cannot exercise Sigma fields (no paths, keys or command lines) |
| Oliveira 2019 | yes, 1,079 | integer-coded API ids, no name table in the re-host | 15 MB | unclear | no arguments; not usable for Sigma |
| Mal-API-2019 | no (malware only) | API names | 2.2 GB | MIT | cross-dataset behaviour test only |
| KHAS API lists | n/a | static PE imports, not behaviour; CSVs truncated against the documented counts | small | none | excluded |
| [Quo Vadis Speakeasy](https://huggingface.co/datasets/dtrizna/quovadis-speakeasy) | yes, 32,673 benign reports | Speakeasy *emulation* reports (APIs with arguments, file and registry access, network per entry point) | about 1.6 GB benign | Apache-2.0 | **used for the benign Sigma FPR** (`specimen/adapters/speakeasy.py`). Caveat: an emulator records fewer host actions than a sandbox (no real registry state, partial process trees), so the benign FPR is a lower bound |

The shipped negative corpus (`specimen/data/negatives.json.gz`) holds event lines from a stratified sample of 200 Avast-CTU *training* runs per family; test-split runs and benign reports are never in it.

## Committed fixtures

- `tests/fixtures/cape/`: four real Avast-CTU reduced reports trimmed to about 8 KB each, plus one clearly synthetic full-format CAPE report.
- `tests/fixtures/sysmon/lab_run.xml`: a synthetic Sysmon XML export (documentation IP ranges, `.invalid` domains) whose event 1 `Hashes` field records the SHA-256 of the inert `lab_sample.bin` next to it.

## Citations

```
Bošanský B., Kouba D., Maňhal O., Sick T., Lisý V., Křoustek J., Somol P. Avast-CTU Public CAPE Dataset. arXiv:2209.03188, 2022.
Anderson H. S., Roth P. EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. arXiv:1804.04637, 2018.
Trizna D. Quo Vadis: Hybrid Machine Learning Meta-Model Based on Contextual and Behavioral Malware Representations. AISec 2022, doi:10.1145/3560830.3563726.
Maniriho P., Mahmood A. N., Chowdhury M. J. M. MalDetConv. arXiv:2209.03547, 2022; API-MalDetect, JNCA 218:103704, 2023, doi:10.1016/j.jnca.2023.103704 (MalbehavD-V1).
Catak F. O., Yazı A. F. A Benchmark API Call Dataset for Windows PE Malware Classification. arXiv:1905.01999, 2019; Catak F. O., Yazı A. F., Elezaj O., Ahmed J. PeerJ Computer Science 6:e285, 2020, doi:10.7717/peerj-cs.285 (Mal-API-2019).
Oliveira A. Malware Analysis Datasets: API Call Sequences. IEEE DataPort, 2019, doi:10.21227/tqqm-aq14.
Li Z., Zhu H., Liu H., Song J., Cheng Q. Comprehensive evaluation of Mal-API-2019 dataset by machine learning in malware detection. IJCSIT 2(1), 2024, doi:10.62051/ijcsit.v2n1.01.
Raff E. et al. Automatic Yara Rule Generation Using Biclustering. AISec 2020, doi:10.1145/3411508.3421372.
```

Machine-readable versions of all of these are in [`CITATION.cff`](https://github.com/rakshit-737/specimen/blob/main/CITATION.cff).
