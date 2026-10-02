# Reproduce

Every published number comes from a script in `benchmarks/` and a JSON file in `results/`. Full-data runs must not run on a shared laptop, so they go through the manual **`bench`** GitHub Actions workflow (`gh workflow run bench -f suite=<suite> -f seeds=5`), which downloads pinned data, runs the suite and uploads `results/` and figures as artefacts; only the small JSON files are committed.

## Data

```bash
export SPECIMEN_DATA=/data/specimen        # anywhere outside the repo
python scripts/download_data.py --dest "$SPECIMEN_DATA"          # Avast 593 MB, EMBER prefix 120 MB, MalbehavD, Mal-API, Oliveira
python scripts/download_data.py --dest "$SPECIMEN_DATA" --verify # checks the pinned SHA-256s, not only SHA256SUMS
python -c "from specimen.ml.avast import build_cache; build_cache()"  # Avast token cache, ~20 min, needed by rules/family
```

A file that does not match its pinned hash is renamed `*.bad` and the script exits non-zero.

## Benchmarks

| result file | command | where | wall clock (reference) | headline key |
|---|---|---|---|---|
| `static_ember_temporal.json` | `bench` workflow, `suite=static-temporal` | Actions (1.7 GB archive) | 29 min | `summary` (AUC 0.989, TPR@0.1% 0.49) |
| `static_ember.json` | `python benchmarks/bench_static.py` | laptop, 120 MB prefix | 33 min | LightGBM AUC 0.994 |
| `rules_avast.json` | `bench` workflow, `suite=rules` (or `python benchmarks/bench_rules.py --seeds 5` under the heavy lock) | Actions | see file `runtime_s` | `summary` |
| `family_avast.json` | `bench` workflow, `suite=family` | Actions | see file | `selected_variant`, accuracy |
| `behaviour_malbehavd.json` | `python benchmarks/bench_malbehavd.py` | laptop, < 1 GB RAM | 2 min | `seeds_70_30`, `dedup_70_30` |
| `repro_maldetconv.json` | `python benchmarks/repro_maldetconv.py` | laptop, CPU PyTorch | see file | paper vs reproduction table |
| `api_cross.json` | `python benchmarks/bench_api_cross.py` | laptop, streamed, < 1.5 GB RAM | see file | cross-dataset and Li et al. tables |

All scripts need `pip install -e ".[ml]"`; the MalDetConv reproduction also needs `torch`. Expected numbers are those in the committed JSON; re-runs on other hardware should agree within the published intervals.

## Demo pages

```bash
gh release download v1.0.0 -R rakshit-737/specimen -p 'family_*' -D models
python scripts/build_demo.py      # regenerates docs/demo/*.md
python -m mkdocs build --strict   # pip install -r docs/requirements.txt
```
