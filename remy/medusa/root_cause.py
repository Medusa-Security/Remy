"""Root-cause engine: explain *why* a request failed, not just that it did.

Agents attach ``parent_id`` links as they work (a click spawns a request,
which spawns a DB call, which throws). When a failure surfaces, we walk those
links backward to reconstruct the causal chain and emit a plain-English
explanation plus the graph path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .events import Event, EventKind, EventStatus


@dataclass
class RootCause:
    failure_id: str
    chain: list[Event]
    explanation: str


def _event_index(events: list[Event]) -> dict[str, Event]:
    return {e.id: e for e in events}


def chain_for(failure_id: str, events: list[Event]) -> list[Event]:
    """Follow parent_id links from a failure event back to its origin."""
    idx = _event_index(events)
    chain: list[Event] = []
    cur: Optional[Event] = idx.get(failure_id)
    guard = 0
    while cur is not None and guard < 64:
        chain.append(cur)
        cur = idx.get(cur.parent_id) if cur.parent_id else None
        guard += 1
    return list(reversed(chain))


def explain(failure_id: str, events: list[Event]) -> Optional[RootCause]:
    idx = _event_index(events)
    failure = idx.get(failure_id)
    if failure is None:
        return None

    chain = chain_for(failure_id, events)

    parts: list[str] = []
    for step in chain:
        dur = f" ({step.duration_ms:.0f}ms)" if step.duration_ms else ""
        parts.append(f"{step.kind.value} {step.target}{dur}".rstrip())

    origin = chain[0] if chain else failure
    explanation = (
        f"'{failure.target}' failed as {failure.status.value}: "
        + " -> ".join(parts)
        + f". Root cause appears at '{origin.target}' ({origin.kind.value})."
    )
    return RootCause(failure_id=failure_id, chain=chain, explanation=explanation)


def find_failures(events: list[Event]) -> list[Event]:
    return [
        e
        for e in events
        if e.status in (EventStatus.ERROR, EventStatus.TIMEOUT)
        or e.kind == EventKind.EXCEPTION
    ]
