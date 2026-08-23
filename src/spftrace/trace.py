"""Structured trace events. The trace is the product, not a side effect."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any


#: Bumped when the shape of Result.to_dict() changes in a way consumers must
#: notice. Additive keys do not bump it.
SCHEMA_VERSION = 1


@dataclass
class Event:
    kind: str
    depth: int
    at_ms: float
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {"kind": self.kind, "depth": self.depth, "at_ms": round(self.at_ms, 1)}
        d.update(self.data)
        return d


class Trace:
    """Ordered event log with depth tracking for include/redirect recursion."""

    def __init__(self) -> None:
        self.t0 = time.monotonic()
        self.events: list[Event] = []
        self.depth = 0

    def now_ms(self) -> float:
        return (time.monotonic() - self.t0) * 1000.0

    def add(self, kind: str, **data: Any) -> Event:
        ev = Event(kind=kind, depth=self.depth, at_ms=self.now_ms(), data=data)
        self.events.append(ev)
        return ev

    def push(self) -> None:
        self.depth += 1

    def pop(self) -> None:
        self.depth = max(0, self.depth - 1)

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self.events]


@dataclass
class DnsQueryRecord:
    name: str
    rtype: str
    rcode: str
    answers: list[str]
    ms: float
    void: bool
    source: str = "dns"  # dns | cache | override

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ms"] = round(self.ms, 1)
        return d


@dataclass
class Result:
    result: str
    explanation: str | None
    trace: Trace
    queries: list[DnsQueryRecord]
    dns_terms_used: int
    void_lookups_used: int
    elapsed_ms: float
    warnings: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """Alias for `result`. `result.result` reads badly in consumer code."""
        return self.result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "result": self.result,
            "explanation": self.explanation,
            "dns_terms_used": self.dns_terms_used,
            "void_lookups_used": self.void_lookups_used,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "warnings": self.warnings,
            "queries": [q.to_dict() for q in self.queries],
            "events": self.trace.to_list(),
        }
