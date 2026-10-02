# ADR 0003: Keep the core standard-library only; put ML behind an extra

- Status: accepted
- Date: 2026-09-26

## Context

The MVP was intentionally dependency-free, which keeps CI fast and makes the
parsing of hostile inputs easy to audit. Real-data models need numpy,
scikit-learn and LightGBM.

## Decision

- `specimen/*` (adapters, provenance, detect, report, CLI) remain standard
  library only.
- `specimen/ml/*` holds the EMBER static model, the Avast token cache and
  the family model, installed with `pip install -e .[ml]`.
- Trained artefacts are written to `models/`, which is gitignored and
  selected with `SPECIMEN_MODELS`. They are stored as a LightGBM text model
  and `.npz` arrays. **No pickle/joblib**, so loading a model can never
  execute code.
- The pipeline loads the family model lazily and falls back cleanly when it
  is missing. It never attributes a real report to a synthetic prototype.

## Consequences

- CI runs the core suite on 3.10-3.14 without ML dependencies, plus an ML
  job. Tests that need downloaded data are marked `realdata` and skip
  cleanly.
- Hashing uses CRC32 buckets instead of scikit-learn's `FeatureHasher`,
  which vectorises about 30x faster per row. Feature indices therefore
  differ from upstream EMBER vectors, and the models are not
  weight-compatible with the official EMBER model.
