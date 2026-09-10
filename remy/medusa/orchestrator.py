"""Medusa Orchestrator — ties the dynamic agents into one coordinated run.

It runs the selected agents against a live :class:`MedusaTarget`, merges every
event and finding into the runtime Event Graph, runs the root-cause engine over
failures, and compares the run against the regression baseline. The result is a
:class:`MedusaReport` that the CLI renders.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .agents import AgentContext
from .agents.api_fuzzer import ApiFuzzerAgent
from .agents.browser import BrowserAgent
from .agents.stateful_e2e import StatefulE2EAgent
from .agents.workflow import WorkflowAgent
from .agents.runtime_tracer import RuntimeTracerAgent
from .events import AgentResult, Event
from .graph_builder import RuntimeGraph, build as build_graph
from .regression import Baseline, RegressionReport, RegressionStore
from .root_cause import RootCause, explain, find_failures
from .target import MedusaTarget

ALL_AGENTS = {
    "browser": BrowserAgent,
    "workflow": WorkflowAgent,
    "api": ApiFuzzerAgent,
    "e2e": StatefulE2EAgent,
    "trace": RuntimeTracerAgent,
}


@dataclass
class MedusaReport:
    run_id: str
    target: str
    timestamp: datetime
    duration_seconds: float
    agent_results: list[AgentResult] = field(default_factory=list)
    graph: Optional[RuntimeGraph] = None
    root_causes: list[RootCause] = field(default_factory=list)
    regression: Optional[RegressionReport] = None
    skipped: list[tuple[str, str]] = field(default_factory=list)

    @property
    def findings(self) -> list:
        out: list = []
        for r in self.agent_results:
            out.extend(r.findings)
        return out

    @property
    def events(self) -> list[Event]:
        out: list[Event] = []
        for r in self.agent_results:
            out.extend(r.events)
        return out


class MedusaOrchestrator:
    def __init__(
        self,
        baseline_dir: str = ".remy/medusa/baselines",
        workflow_path: Optional[str] = None,
    ) -> None:
        self.baseline_store = RegressionStore(baseline_dir)
        self.workflow_path = workflow_path

    def select(self, names: Optional[list[str]]) -> dict:
        if not names or "all" in names:
            return dict(ALL_AGENTS)
        unknown = [n for n in names if n not in ALL_AGENTS]
        if unknown:
            raise ValueError(
                f"Unknown agents: {unknown}. Available: {sorted(ALL_AGENTS)}"
            )
        return {n: ALL_AGENTS[n] for n in names}

    def run(
        self,
        target: MedusaTarget,
        agents: Optional[list[str]] = None,
        regression: bool = True,
    ) -> MedusaReport:
        start = time.perf_counter()
        run_id = str(uuid.uuid4())[:8]
        ctx = AgentContext()
        results: list[AgentResult] = []
        skipped: list[tuple[str, str]] = []

        selected = self.select(agents)
        for name, cls in selected.items():
            agent = cls() if name != "workflow" else cls(self.workflow_path)
            if not agent.available():
                skipped.append((name, "dependency unavailable"))
                results.append(
                    AgentResult(
                        agent=name, skipped=True, skip_reason="dependency unavailable"
                    )
                )
                continue
            try:
                results.append(agent.run(target, ctx))
            except Exception as e:  # noqa: BLE001
                skipped.append((name, str(e)))
                results.append(
                    AgentResult(agent=name, skipped=True, skip_reason=str(e))
                )

        ctx.findings = _dedupe_findings(ctx.findings)
        graph = build_graph(ctx.events, ctx.findings)

        root_causes: list[RootCause] = []
        for failure in find_failures(ctx.events):
            rc = explain(failure.id, ctx.events)
            if rc:
                root_causes.append(rc)

        reg_report: Optional[RegressionReport] = None
        if regression:
            counts: dict[str, int] = {}
            for f in ctx.findings:
                sev = (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity)
                )
                counts[sev] = counts.get(sev, 0) + 1
            p95 = _p95_latency(ctx.events)
            baseline = Baseline(
                target=target.base_url,
                duration_seconds=round(time.perf_counter() - start, 2),
                finding_counts=counts,
                endpoints_covered=len(
                    {e.target for e in ctx.events if e.kind.name == "REQUEST"}
                ),
                p95_latency_ms=p95,
                error_count=len(find_failures(ctx.events)),
            )
            reg_report = self.baseline_store.compare(baseline, ctx.findings)
            self.baseline_store.save(baseline)

        return MedusaReport(
            run_id=run_id,
            target=target.base_url,
            timestamp=datetime.now(),
            duration_seconds=round(time.perf_counter() - start, 2),
            agent_results=results,
            graph=graph,
            root_causes=root_causes,
            regression=reg_report,
            skipped=skipped,
        )


def _p95_latency(events: list[Event]) -> float:
    durations = sorted(e.duration_ms for e in events if e.duration_ms > 0)
    if not durations:
        return 0.0
    idx = max(0, int(len(durations) * 0.95) - 1)
    return round(durations[idx], 1)


def _dedupe_findings(findings: list) -> list:
    """Collapse duplicate findings by (scanner, title, location)."""
    seen: set[tuple] = set()
    out: list = []
    for f in findings:
        loc = f.file
        key = (f.scanner, f.title, loc)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
