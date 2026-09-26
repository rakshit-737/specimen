PY ?= python
SPECIMEN_DATA ?= data
export SPECIMEN_DATA

.PHONY: install test lint demo data cache bench bench-static bench-family bench-rules bench-behaviour clean

install:
	$(PY) -m pip install -e ".[dev,ml]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

demo:
	$(PY) -m specimen demo --out out
	$(PY) -m specimen report tests/fixtures/cape/avast_lokibot_1.json --out out/reports

data:
	$(PY) scripts/download_data.py --dest $(SPECIMEN_DATA)

cache:
	$(PY) -c "from specimen.ml.avast import build_cache; build_cache()"

bench-static:
	$(PY) benchmarks/bench_static.py

bench-family: cache
	$(PY) benchmarks/bench_family.py

bench-rules: cache
	$(PY) benchmarks/bench_rules.py

bench-behaviour:
	$(PY) benchmarks/bench_malbehavd.py

bench: bench-static bench-family bench-rules bench-behaviour

clean:
	$(PY) -c "import shutil; [shutil.rmtree(p, True) for p in (\"out\", \".pytest_cache\")]"
