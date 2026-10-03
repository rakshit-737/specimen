# Getting started

## Try it in 60 seconds

The core is stdlib-only, so nothing but Python 3.10+ is needed:

```bash
git clone https://github.com/rakshit-737/specimen && cd specimen
pip install -e .
python -m specimen demo --out out
python -m specimen report tests/fixtures/cape/avast_njrat_1.json --out out/reports
python -m specimen batch tests/fixtures/cape --out out/batch --workers 2
python -m specimen analyze tests/fixtures/sysmon/lab_sample.bin --trace tests/fixtures/sysmon/lab_run.xml --force-detonate --out out/sysmon
```

CI runs the same block from the README on every push. `lab_sample.bin` is an inert dummy file; the Sysmon fixture records its SHA-256 in event 1 `Hashes`, so `analyze` refuses any other sample with that trace.

Without the trained models, the report's `family` is `null`, nothing is left out of the packaged negative corpus (so fewer Sigma rules survive), and reduced reports, which have no API call log, are scored by the MVP ATT&CK-feature scorer. The API behaviour model ships inside the package.

## Full install and trained models

```bash
pip install -e ".[dev,ml]"                # [ml] adds numpy / scikit-learn / LightGBM
python -m pytest -q                       # no datasets needed
python scripts/fetch_models.py --dest models   # SHA-256 pinned in scripts/model_assets.json
# without a clone: gh release download -R rakshit-737/specimen -p 'family_*' -p 'static_*' -D models
```

The family model (`family_model.npz`, about 5.7 MB) and the EMBER gate (`static_lgbm.txt`, about 4.4 MB) exceed the 1 MB repository limit and are release assets; put them in `models/` or point `SPECIMEN_MODELS` at them. `triage-ember` names any missing file. No model is ever unpickled.

## Your own inputs

```bash
python -m specimen analyze <your-sample> --trace <recorded-run.json|sysmon.xml> --out out/
python -m specimen batch <your-report-dir> --out out/batch --workers 4
python -m specimen triage-ember <ember-raw-features.jsonl>
```

## Docker

```bash
docker run --rm --network none --read-only -v "$PWD/tests/fixtures:/fx:ro" \
  ghcr.io/rakshit-737/specimen:latest report /fx/cape/avast_njrat_1.json
# write reports to the host: run as your own uid
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD/tests/fixtures:/fx:ro" -v "$PWD/out:/out" \
  ghcr.io/rakshit-737/specimen:latest report /fx/cape/avast_njrat_1.json --out /out
```

The image contains no family or EMBER model; mount them with `-v "$PWD/models:/opt/specimen/models:ro"`. Pin a release with `:v1.1.0`; releases after 1.1.0 are also tagged with the plain version (for example `:1.2.0`) and carry `org.opencontainers.image.version` and `revision` labels.

Benchmarks: see [Reproduce](reproduce.md).
