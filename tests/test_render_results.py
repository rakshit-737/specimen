"""The generated result blocks must be filled, and an empty block must be detected."""
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("render_results", ROOT / "scripts" / "render_results.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)

_EMPTY = re.compile(r"<!-- gen:([a-z0-9-]+) -->\r?\n<!-- /gen:\1 -->")


def test_empty_block_matches_the_block_pattern():
    text = "a\n<!-- gen:cross -->\n<!-- /gen:cross -->\nb\n"
    m = rr._BLOCK.search(text)
    assert m is not None and m.group(2) == "cross"


def test_no_committed_block_is_empty():
    empty = [f"{p.name}:{m.group(1)}" for p in rr.TARGETS
             for m in _EMPTY.finditer(p.read_text(encoding="utf-8"))]
    assert not empty, f"empty generated blocks (run scripts/render_results.py): {empty}"
