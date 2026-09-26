import json

import pytest

from specimen.models import Event
from specimen.trace import TraceError, load_trace, parse_trace


def test_load_sorted(fx):
    t = load_trace(fx["sim_ransom.bin"][1])
    ts = [e.ts for e in t.events]
    assert ts == sorted(ts) and len(t.source_sha256) == 64


@pytest.mark.parametrize("raw", [b"nope", b"[]", b'{"events": [{"type": "boom"}]}',
                                 b'{"events": [{"type": "file_read", "ts": 1}]}'])
def test_rejects_bad(raw):
    with pytest.raises(TraceError):
        parse_trace(raw)


def test_event_validation():
    with pytest.raises(ValueError):
        Event(-1, "file_read", 1, "x")


def test_extra_fields_kept():
    raw = json.dumps({"events": [{"ts": 1, "type": "process_create", "pid": 1, "image": "a",
                                  "target": "b", "child_pid": 9}]}).encode()
    assert parse_trace(raw).events[0].extra["child_pid"] == 9
