"""Agent 5 — Runtime Tracing.

Every request is instrumented as a span. The tracer assembles REQUEST/RESPONSE/
DB_QUERY/QUEUE/EXCEPTION events (emitted by the other agents) into per-request
traces and a service-dependency map (browser -> express -> redis -> celery ->
openai -> db). It flags anomalous traces — a request whose subtree contains a
timeout, retry, or error — which the orchestrator's root-cause engine then
explains. A ``Tracer`` instrumentor is also provided so any agent can capture
spans for free via response headers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..agents import AgentContext, BaseAgent
from ..events import AgentResult, Event, EventKind
from ..target import MedusaTarget
from remy.report.models import Severity


@dataclass
class Span:
    id: str
    name: str
    service: str
    parent_id: Optional[str]
    duration_ms: float
    status: str
    meta: dict = field(default_factory=dict)


@dataclass
class Trace:
    root_id: str
    endpoint: str
    spans: list[Span] = field(default_factory=list)

    @property
    def has_error(self) -> bool:
        return any(s.status in ("error", "timeout") for s in self.spans)


def build_traces(events: list[Event]) -> list[Trace]:
    by_parent: dict[Optional[str], list[Event]] = {}
    for e in events:
        by_parent.setdefault(e.parent_id, []).append(e)

    traces: list[Trace] = []
    for root in by_parent.get(None, []):
        if root.kind != EventKind.REQUEST:
            continue
        spans: list[Span] = []
        queue = [root]
        while queue:
            cur = queue.pop(0)
            service = "client"
            if cur.kind == EventKind.REQUEST:
                service = "gateway"
            elif cur.kind in (EventKind.DB_QUERY, EventKind.QUEUE):
                service = cur.target.split(":")[0] if ":" in cur.target else cur.target
            spans.append(
                Span(
                    id=cur.id,
                    name=cur.kind.value,
                    service=service,
                    parent_id=cur.parent_id,
                    duration_ms=cur.duration_ms,
                    status=cur.status.value,
                    meta=cur.meta,
                )
            )
            queue.extend(by_parent.get(cur.id, []))
        traces.append(Trace(root_id=root.id, endpoint=root.target, spans=spans))
    return traces


class RuntimeTracerAgent(BaseAgent):
    name = "runtime-tracer"

    def run(self, target: MedusaTarget, ctx: AgentContext) -> AgentResult:
        traces = build_traces(ctx.events)
        error_traces = [t for t in traces if t.has_error]

        for t in error_traces:
            ctx.finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                title=f"Anomalous runtime trace ({t.endpoint})",
                detail=f"Trace contained an error/timeout across {len(t.spans)} spans.",
                location=t.endpoint,
                cwe="CWE-755",
                remediation="Inspect the trace with `remy medusa --explain`; fix the failing span.",
            )

        service_map = self._service_map(ctx)
        return AgentResult(
            agent=self.name,
            events=ctx.events,
            findings=ctx.findings,
            summary={
                "traces": len(traces),
                "error_traces": len(error_traces),
                "services": service_map,
            },
        )

    @staticmethod
    def _service_map(ctx: AgentContext) -> dict[str, list[str]]:
        """Map each endpoint to the downstream services it touched (from event meta)."""
        out: dict[str, list[str]] = {}
        for e in ctx.events:
            if e.kind == EventKind.REQUEST:
                svc = e.meta.get("services", [])
                if isinstance(svc, list):
                    out.setdefault(e.target, [])
                    for s in svc:
                        if s not in out[e.target]:
                            out[e.target].append(s)
        return out


class Tracer:
    """Optional instrumentor: wrap an httpx request to capture a span + downstream services."""

    def __init__(self, ctx: AgentContext, agent: str) -> None:
        self.ctx = ctx
        self.agent = agent

    def request(self, client, method: str, path: str, **kw) -> object:
        import time

        import httpx

        ev = self.ctx.request(self.agent, f"{method} {path}")
        t0 = time.perf_counter()
        try:
            r = client.request(method, path, **kw)
            dt = (time.perf_counter() - t0) * 1000
            self.ctx.response(self.agent, f"{method} {path}", parent=ev.id, duration_ms=dt)
            services = r.headers.get("x-remy-services")
            if services:
                ev.meta["services"] = [s.strip() for s in services.split(",")]
                for s in ev.meta["services"]:
                    self.ctx.emit(
                        Event.make(
                            EventKind.QUEUE if "queue" in s else EventKind.DB_QUERY,
                            self.agent,
                            f"{s}:{path}",
                            parent_id=ev.id,
                        )
                    )
            return r
        except httpx.HTTPError as e:
            dt = (time.perf_counter() - t0) * 1000
            self.ctx.exception(self.agent, f"{method} {path}", parent=ev.id, duration_ms=dt, detail=str(e))
            raise
