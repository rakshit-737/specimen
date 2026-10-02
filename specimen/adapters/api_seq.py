"""API-call-sequence datasets (e.g. MalbehavD-V1, Cuckoo-derived) -> ``Trace``.

Such datasets keep only the ordered API names per sample, so every call
becomes an ``api_call`` event with its sequence index as timestamp.
"""
from __future__ import annotations

from collections.abc import Sequence

from ..models import Event, Trace

MAX_CALLS = 10_000


def api_sequence_to_trace(apis: Sequence[str], run_id: str, sample_sha256: str = "",
                          image: str = "sample.exe") -> Trace:
    """Convert an ordered list of API names into a ``Trace`` of ``api_call`` events.

    :param apis: API names in call order; empty entries are skipped and at most ``MAX_CALLS`` are kept.
    :param run_id: identifier stored on the trace.
    :param sample_sha256: hash of the sample, if known.
    :param image: process image name given to every event.
    :returns: a ``Trace`` whose event timestamps are the sequence indices.
    """
    evs = [Event(float(i), "api_call", 1000, image, target=str(a)[:128])
           for i, a in enumerate(apis[:MAX_CALLS]) if a]
    return Trace(run_id, sample_sha256, "api-sequence", evs)
