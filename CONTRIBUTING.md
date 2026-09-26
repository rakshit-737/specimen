# Contributing to SPECIMEN

Thanks for your interest. SPECIMEN is a defensive, lab-only project. Read
[SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) before you
start.

## Ground rules

- **Never commit or attach malware**, packed samples, password-protected
  archives or memory dumps. Use hashes, public sandbox reports and the inert
  fixtures in `specimen/lab_fixtures.py`.
- **Never commit datasets or files over 1 MB.** Data is fetched by
  `scripts/download_data.py` into `$SPECIMEN_DATA`, which lives outside the
  repo. Trained models go to `models/` (gitignored).
- The core package (`specimen/`, excluding `specimen/ml/`) stays standard
  library only. See [ADR 0003](docs/adr/0003-optional-ml-stack.md).
- Model artefacts are loaded from text or `.npz` files only. Do not use
  pickle or joblib.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,ml]"
python -m pytest -q                                # core + ML tests, real-data tests skip
python -m ruff check .
```

To run the real-data tests and benchmarks, fetch the data first
(about 720 MB):

```bash
export SPECIMEN_DATA=/path/outside/repo
python scripts/download_data.py --dest "$SPECIMEN_DATA"
python -m pytest -q -m realdata
```

## Pull requests

- Keep commits small and use conventional-commit prefixes: `feat:`, `fix:`,
  `test:`, `docs:`, `data:`, `perf:`, `refactor:`, `ci:`, `build:`.
- Add or adjust tests for every behaviour change. CI must stay green without
  the datasets.
- If you change a benchmark, re-run it, commit the updated `results/*.json`
  and figures, and update the README tables. Report numbers honestly,
  including regressions.
- Document design decisions that others would otherwise have to rediscover
  as an ADR in `docs/adr/`.

## Adding a sandbox adapter

Adapters live in `specimen/adapters/` and return a `specimen.models.Trace`.
They must treat their input as hostile: coerce types, truncate strings, cap
list sizes, and ignore unknown shapes rather than raising. Add a small real
(or clearly synthetic) fixture under `tests/fixtures/`.
