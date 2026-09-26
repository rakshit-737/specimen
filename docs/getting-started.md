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

`models/` ships the trained artefacts: the EMBER LightGBM static gate (text), the Avast-CTU family model (`.npz`) and the MalbehavD-V1 API n-gram behaviour scorer (JSON, pure-Python inference). None of them is ever unpickled. Point `SPECIMEN_MODELS` elsewhere to use your own.
