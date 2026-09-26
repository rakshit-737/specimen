PY ?= python

.PHONY: demo test install clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m specimen demo --out out

clean:
	$(PY) -c "import shutil; [shutil.rmtree(p, True) for p in ('out', '.pytest_cache')]"
