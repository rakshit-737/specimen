# Getting started

## Install

```bash
git clone https://github.com/rakshit-737/specimen && cd specimen
pip install -e ".[dev,ml]"   # the core is stdlib-only; [ml] adds numpy/scikit-learn/LightGBM
python -m pytest -q          # no datasets needed
```

Or with Docker (image published on each release):

```bash
docker run --rm -v "$PWD:/work" ghcr.io/rakshit-737/specimen:latest report /work/report.json --out /work/out
```

## Try it

```bash
# inert fixtures, all spec demo scenarios
python -m specimen demo --out out

# report-only analysis of a bundled (trimmed, public) Avast-CTU CAPE report
python -m specimen report tests/fixtures/cape/avast_njrat_1.json --out out/reports

# sample bytes + a recorded run; the run may be a native trace, a CAPE/Cuckoo
# JSON report, or a Sysmon export (wevtutil /f:xml or JSON lines)
python -m specimen analyze sample.bin --trace tests/fixtures/sysmon/lab_run.xml --force-detonate --out out

# a whole directory of CAPE reports, resumable
python -m specimen batch path/to/reports --out out/batch --workers 4
```

## Real data and benchmarks

```bash
export SPECIMEN_DATA=/data/specimen            # outside the repo
python scripts/download_data.py --dest "$SPECIMEN_DATA"
python benchmarks/bench_static.py
python benchmarks/bench_family.py
python benchmarks/bench_rules.py
python benchmarks/bench_malbehavd.py
```

`make` targets (`make data`, `make bench`, `make demo`) wrap the same commands.

## Models

Only the MalbehavD-V1 API n-gram behaviour scorer (`models/api_behaviour.json`, pure-Python inference, ~few hundred KB) is committed. The EMBER LightGBM gate (`static_lgbm.txt`, 4.4 MB) and the Avast-CTU family model (`family_model.npz`, 5.8 MB) exceed the repository's 1 MB file limit: they are rebuilt by `bench_static.py` / `bench_family.py` and attached to the GitHub Release as assets. Drop them into `models/` (or point `SPECIMEN_MODELS` elsewhere) to enable the trained gate and family attribution. No model is ever unpickled.
