"""Event model for the Medusa runtime agents.

Every agent records what it did as an :class:`Event`. Events are linked into
the Event Graph (see :mod:`remy.medusa.graph_builder`) and, when something
goes wrong, the :mod:`remy.medusa.root_cause` engine walks the parent links
to explain *why* a request failed instead of just reporting a 500.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EventStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    WARN = "warn"


class EventKind(str, Enum):
    NAVIGATE = "navigate"
    CLICK = "click"
    FILL = "fill"
    SUBMIT = "submit"
    REQUEST = "request"
    RESPONSE = "response"
    EXCEPTION = "exception"
    TIMEOUT = "timeout"
    DB_QUERY = "db_query"
    QUEUE = "queue"
    TRANSITION = "transition"
    STATE = "state"


@dataclass
class Event:
    id: str
    kind: EventKind
    agent: str
    target: str
    status: EventStatus = EventStatus.OK
    duration_ms: float = 0.0
    detail: str = ""
    parent_id: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def make(cls, kind: EventKind, agent: str, target: str, **kw: Any) -> "Event":
        return cls(
            id=str(uuid.uuid4())[:8],
            kind=kind,
            agent=agent,
            target=target,
            **kw,
        )


@dataclass
class AgentResult:
    """Everything a single agent produced during one run."""

    agent: str
    events: list[Event] = field(default_factory=list)
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    skipped: bool = False
    skip_reason: str = ""
