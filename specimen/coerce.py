"""Coercion helpers for hostile report and trace values (standard library only).

Sandbox reports and traces come from the environment that ran the sample, so
numbers may be ``NaN``, ``Infinity``, ``1e999`` or the wrong type, and JSON may
be nested deeply enough to exhaust the parser's recursion limit. These helpers
turn such values into defaults or a :class:`ValueError` with a clear message,
never into an unhandled ``OverflowError`` / ``RecursionError`` traceback.
"""
from __future__ import annotations

import json
import math
from typing import Any


def finite_float(v: Any, default: float = 0.0, lo: float | None = None, hi: float | None = None) -> float:
    """``float(v)`` if it is a finite number (optionally clamped to ``[lo, hi]``), else ``default``."""
    if isinstance(v, bool):
        return default
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(f):
        return default
    if lo is not None:
        f = max(lo, f)
    if hi is not None:
        f = min(hi, f)
    return f


def safe_int(v: Any, default: int = 0) -> int:
    """``int(v)`` for finite numbers and integer strings, else ``default`` (never raises)."""
    if isinstance(v, bool):
        return default
    if isinstance(v, float):
        return int(v) if math.isfinite(v) else default
    try:
        return int(str(v).strip(), 0) if isinstance(v, str) and v.strip().lower().startswith("0x") else int(v)
    except (TypeError, ValueError, OverflowError):
        return default


def loads(raw: bytes | str, what: str = "input") -> Any:
    """``json.loads`` for untrusted input.

    :raises ValueError: on invalid JSON, undecodable bytes or nesting deep
        enough to exhaust the parser's recursion limit.
    """
    try:
        return json.loads(raw)
    except RecursionError as e:
        raise ValueError(f"{what}: JSON nested too deeply") from e
    except UnicodeDecodeError as e:
        raise ValueError(f"{what}: not UTF-8/16/32 JSON ({e.reason})") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"{what}: invalid JSON: {e}") from e
