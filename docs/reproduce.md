# Reproduce

Every published number comes from a script in `benchmarks/` and a JSON file in `results/`. All of them run in the manual **`bench`** GitHub Actions workflow, so each result file records the run id, job, commit, command and runtime that produced it (`provenance`):

```bash
gh workflow run bench -R rakshit-737/specimen -f suite=all -f seeds=5
# suites: rules | family | avast (rules+family) | static-temporal | static | malbehavd | api-cross | maldetconv | light | all
```

The workflow downloads pinned data (SHA-256 checked; the whole 1.7 GB EMBER archive and the 1.6 GB Speakeasy reports only ever inside Actions), runs the suite, checks every result file (`scripts/check_results.py`: provenance, finite values, proportions and intervals in [0, 1]) and uploads `results/`, figures and model files as artefacts. Only the small JSON files are committed; `python scripts/render_results.py` then regenerates every table in the README and on these pages, and CI fails if they drift.

## Benchmarks

<!-- gen:reproduce -->
<!-- /gen:reproduce -->

All scripts need `pip install -e ".[ml]"`; `api-cross` also needs `xgboost`, `maldetconv` needs CPU `torch`, and the benign Speakeasy cache needs `huggingface_hub`. Every script has `--help` and exits with a one-line hint when its data is missing.

## Data, locally

```bash
export SPECIMEN_DATA=/data/specimen        # anywhere outside the repo
python scripts/download_data.py --dest "$SPECIMEN_DATA"          # Avast 593 MB, EMBER prefix 120 MB, MalbehavD, Mal-API, Oliveira
python scripts/download_data.py --dest "$SPECIMEN_DATA" --verify # checks the pinned SHA-256s, not only SHA256SUMS
python -c "from specimen.ml.avast import build_cache; build_cache()"  # Avast token cache, needed by rules/family
```

A file that does not match its pinned hash is renamed `*.bad` and the script exits non-zero. The benign Speakeasy reports (`scripts/build_speakeasy_cache.py`) and the whole EMBER archive (`--ember-mb 0`) are over 1 GB and belong in the `bench` workflow, not on a shared laptop.

## Models

The trained family model and the EMBER gate are too large for git. `scripts/model_assets.json` pins their SHA-256s and says where they come from; `python scripts/fetch_models.py` downloads them from the pinned release, else the latest release, else the `bench` artefact that produced them, and refuses any file whose hash differs. `release.yml` attaches the same files to every release and lists their SHA-256s in the release notes.

## Demo pages

```bash
python scripts/fetch_models.py --only family_   # pinned family model, SHA-256 verified
python scripts/build_demo.py                     # regenerates docs/demo/*.md and docs/demo/summary.json
python scripts/render_results.py                 # README example and walkthrough numbers
python -m mkdocs build --strict                  # pip install -r docs/requirements.txt
```

The docs workflow runs the same commands and fails if the regenerated demo index differs from the committed one.
