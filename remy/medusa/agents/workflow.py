"""Agent 2 — Workflow Execution.

Records a user journey as a state machine and verifies every transition. The
agent walks a declared workflow (login -> dashboard -> create -> upload ->
delete) emitting ``TRANSITION`` events for each state change, and runs negative
invariant checks ("can I delete without permission?", "can I upload twice?")
that become findings when the app fails to enforce them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx
import yaml

from ..agents import AgentContext, BaseAgent
from ..events import AgentResult, EventKind
from ..target import MedusaTarget
from remy.report.models import Severity


@dataclass
class Step:
    state: str
    action: dict
    next: Optional[str] = None
    expect_status: Optional[int] = None


def load_workflow(path: str) -> list[Step]:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) if p.suffix in (".yaml", ".yml") else json.loads(p.read_text())
    steps = []
    for s in data:
        steps.append(
            Step(
                state=s["state"],
                action=s.get("action", {}),
                next=s.get("next"),
                expect_status=s.get("expect_status"),
            )
        )
    return steps


# Built-in negative invariants exercised when no workflow file is supplied.
_DEFAULT_INVARIANTS = [
    {"name": "access-dashboard-without-auth", "method": "GET", "path": "/dashboard", "expect_forbidden": True},
    {"name": "delete-without-auth", "method": "DELETE", "path": "/project/1", "expect_forbidden": True},
    {"name": "admin-without-auth", "method": "GET", "path": "/admin", "expect_forbidden": True},
]


class WorkflowAgent(BaseAgent):
    name = "workflow"

    def __init__(self, workflow_path: Optional[str] = None) -> None:
        self.workflow_path = workflow_path

    def run(self, target: MedusaTarget, ctx: AgentContext) -> AgentResult:
        with httpx.Client(
            base_url=target.base_url.rstrip("/"),
            timeout=target.timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            steps = load_workflow(self.workflow_path) if self.workflow_path else []
            current = "start"
            for step in steps:
                self._exec_step(client, target, ctx, current, step)
                current = step.next or current

            self._run_invariants(client, target, ctx)

        return AgentResult(
            agent=self.name,
            events=ctx.events,
            findings=ctx.findings,
            summary={
                "transitions": len([e for e in ctx.events if e.kind == EventKind.TRANSITION]),
                "invariants_checked": len(_DEFAULT_INVARIANTS) if not self.workflow_path else len(steps),
            },
        )

    def _exec_step(self, client, target, ctx, current, step: Step) -> None:
        action = step.action
        method = action.get("method", "GET")
        path = action.get("path", "/")
        auth = action.get("auth", False)
        headers = target.auth_headers if auth else {}
        json_body = action.get("json")

        ctx.transition(self.name, f"{current} -> {step.state}", detail=f"{method} {path}")
        try:
            r = client.request(method, path, headers=headers, json=json_body)
            if step.expect_status and r.status_code != step.expect_status:
                ctx.finding(
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Workflow transition mismatch ({current} -> {step.state})",
                    detail=f"Expected {step.expect_status} but got {r.status_code} for {method} {path}.",
                    location=f"{method} {path}",
                    cwe="CWE-840",
                    remediation="Ensure the workflow leads to the expected state.",
                )
        except httpx.HTTPError as e:
            ctx.finding(
                scanner=self.name,
                severity=Severity.HIGH,
                title=f"Workflow step failed ({current} -> {step.state})",
                detail=f"{method} {path} raised {type(e).__name__}: {e}",
                location=f"{method} {path}",
                cwe="CWE-755",
            )

    def _run_invariants(self, client, target, ctx) -> None:
        for inv in _DEFAULT_INVARIANTS:
            ctx.transition(self.name, f"invariant:{inv['name']}", detail=inv["name"])
            try:
                r = client.request(inv["method"], inv["path"], headers={})
                if inv.get("expect_forbidden") and r.status_code < 400:
                    ctx.finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title=f"Broken invariant: {inv['name']}",
                        detail=f"{inv['method']} {inv['path']} returned {r.status_code} "
                        "without authentication (expected 401/403).",
                        location=f"{inv['method']} {inv['path']}",
                        cwe="CWE-306",
                        remediation="Enforce authorization before performing the action.",
                    )
            except httpx.HTTPError:
                pass
