# Datasets

Nothing is committed to git. `scripts/download_data.py` fetches the data into `$SPECIMEN_DATA` (outside the repo) with resumable range requests and records SHA-256 hashes in `SHA256SUMS` (`--verify` re-checks them). Only sandbox reports, pre-extracted features and API sequences are downloaded, never binaries.

| Dataset | What is used | Size | Licence | Citation |
|---|---|---|---|---|
| [Avast-CTU Public CAPEv2](https://github.com/avast/avast-ctu-cape-dataset) | Reduced reports (`behavior.summary` + `static.pe`) for 48,976 samples in 10 families, labels and dates | 593 MB zip | MIT (per `Licences.txt`) | Bošanský et al., *Avast-CTU Public CAPE Dataset*, arXiv:2209.03188 (2022) |
| [EMBER 2018 v2](https://github.com/elastic/ember) | Raw feature JSON lines; only a 120 MB prefix of the 1.7 GB archive (56,893 labelled rows) | 120 MB | data: MIT | Anderson & Roth, *EMBER*, arXiv:1804.04637 (2018) |
| [MalbehavD-V1](https://github.com/mpasco/MalbehavD-V1) | Cuckoo API-call sequences, 1,285 benign + 1,285 malicious | 2.3 MB | MIT | Maniriho et al., *MalDetConv*, arXiv:2209.03547 (2022); *API-MalDetect*, JNCA 2023 |

## Committed fixtures

- `tests/fixtures/cape/`: four real Avast-CTU reduced reports trimmed to about 8 KB each, plus one clearly synthetic full-format CAPE report.
- `tests/fixtures/sysmon/lab_run.xml`: a synthetic Sysmon XML export (documentation IP ranges, `.invalid` domains).

## Citations

```
Bošanský B., Kouba D., Maňhal O., Sick T., Lisý V., Křoustek J., Somol P. Avast-CTU Public CAPE Dataset. arXiv:2209.03188, 2022.
Anderson H. S., Roth P. EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. arXiv:1804.04637, 2018.
Maniriho P., Mahmood A. N., Chowdhury M. J. M. MalDetConv / API-MalDetect. arXiv:2209.03547, 2022; JNCA 218, 2023.
```
