"""Agent protocol and shared collection context for Medusa."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from remy.report.models import Finding, Severity

from ..events import AgentResult, Event, EventKind, EventStatus


class MedusaAgentError(Exception):
    """Raised when an agent cannot run (e.g. missing optional dependency)."""


@dataclass
class AgentContext:
    """Shared sink for everything the agents emit during one orchestrated run."""

    events: list[Event] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    _seq: int = 0

    def emit(self, event: Event) -> Event:
        self.events.append(event)
        return event

    def click(
        self, agent: str, target: str, parent: Optional[str] = None, **kw: object
    ) -> Event:
        return self.emit(
            Event.make(EventKind.CLICK, agent, target, parent_id=parent, **kw)
        )

    def navigate(self, agent: str, target: str, **kw: object) -> Event:
        return self.emit(Event.make(EventKind.NAVIGATE, agent, target, **kw))

    def request(
        self, agent: str, target: str, parent: Optional[str] = None, **kw: object
    ) -> Event:
        return self.emit(
            Event.make(EventKind.REQUEST, agent, target, parent_id=parent, **kw)
        )

    def response(self, agent: str, target: str, parent: str, **kw: object) -> Event:
        return self.emit(
            Event.make(EventKind.RESPONSE, agent, target, parent_id=parent, **kw)
        )

    def exception(
        self, agent: str, target: str, parent: Optional[str] = None, **kw: object
    ) -> Event:
        return self.emit(
            Event.make(
                EventKind.EXCEPTION,
                agent,
                target,
                parent_id=parent,
                status=EventStatus.ERROR,
                **kw,
            )
        )

    def transition(
        self, agent: str, target: str, parent: Optional[str] = None, **kw: object
    ) -> Event:
        return self.emit(
            Event.make(EventKind.TRANSITION, agent, target, parent_id=parent, **kw)
        )

    def finding(
        self,
        scanner: str,
        severity: Severity,
        title: str,
        detail: str,
        location: str,
        cwe: Optional[str] = None,
        remediation: str = "",
        confidence: float = 0.8,
    ) -> Finding:
        f = Finding(
            id=f"{scanner}:{self._seq}",
            scanner=scanner,
            severity=severity,
            cwe=cwe,
            file=location,
            line_start=0,
            line_end=0,
            title=title,
            description=detail,
            remediation_hint=remediation or "Review and fix.",
            confidence=confidence,
        )
        self._seq += 1
        self.findings.append(f)
        return f


class BaseAgent:
    """Base class for all Medusa agents.

    Subclasses implement :meth:`run`. If an agent needs an optional dependency
    it does not have, it should raise :class:`MedusaAgentError` from
    :meth:`run` (or override :meth:`available`); the orchestrator will then
    mark it skipped rather than failing the whole run.
    """

    name: str = "base"

    def available(self) -> bool:
        return True

    def run(self, target, ctx: AgentContext) -> AgentResult:
        raise NotImplementedError
