"""Typed data models shared across pipeline stages."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

EVENT_TYPES = frozenset({
    "process_create", "process_inject", "file_write", "file_read", "file_delete",
    "registry_set", "net_connect", "dns_query", "service_create", "scheduled_task",
    "api_call", "mutex_create", "registry_delete", "registry_read", "service_start",
})


@dataclass(frozen=True)
class Sample:
    path: str
    sha256: str
    md5: str
    size: int


@dataclass
class Contribution:
    feature: str
    value: float
    weight: float
    impact: float = field(init=False)

    def __post_init__(self) -> None:
        self.impact = round(self.value * self.weight, 4)


@dataclass
class StaticVerdict:
    score: float                 # 0..1
    label: str                   # benign | suspicious | malicious
    detonate: bool
    reasons: list[Contribution] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    entropy: float = 0.0
    is_pe: bool = False


@dataclass(frozen=True)
class Event:
    ts: float
    type: str
    pid: int
    image: str
    ppid: int | None = None
    target: str | None = None
    cmdline: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {self.type!r}")
        if self.ts < 0:
            raise ValueError("negative timestamp")


@dataclass
class Trace:
    run_id: str
    sample_sha256: str
    sandbox: str
    events: list[Event]
    source_sha256: str = ""


@dataclass(frozen=True)
class Node:
    id: str
    kind: str      # process | file | registry | network | domain | service | task
    label: str


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    relation: str
    ts: float


@dataclass
class TimelineEntry:
    ts: float
    description: str
    technique: str | None
    tactic: str | None
    anomaly: float = 0.0


@dataclass
class BehaviorScore:
    probability: float
    label: str
    contributions: list[Contribution] = field(default_factory=list)
    family: str | None = None
    family_similarity: float = 0.0
    family_model: str = "synthetic-prototypes"
    family_evidence: list = field(default_factory=list)
    scorer: str = "mvp-synthetic-logreg (ATT&CK features)"


@dataclass
class Detections:
    yara: str | None
    sigma: list[str]
    yara_fp_hits: list[str] = field(default_factory=list)
    sigma_fp_hits: list[str] = field(default_factory=list)


def to_dict(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, list):
        return [to_dict(o) for o in obj]
    return obj
