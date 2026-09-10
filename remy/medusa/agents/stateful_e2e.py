"""Agent 4 — Stateful End-to-End Testing.

Most tools stop at one request. This agent remembers previous actions across
sessions: User A creates a project, uploads a file, triggers an AI scan; the
worker finishes; User B (a different session) tries to touch A's data; the
owner deletes the account and refreshes. Persistent cookies/JWT per session
make it stateful, and cross-session isolation + post-delete consistency are
checked for regressions.
"""

from __future__ import annotations

import time
from typing import Optional

import httpx

from ..agents import AgentContext, BaseAgent
from ..events import AgentResult, EventKind
from ..target import MedusaTarget
from remy.report.models import Severity


class StatefulE2EAgent(BaseAgent):
    name = "stateful-e2e"

    def run(self, target: MedusaTarget, ctx: AgentContext) -> AgentResult:
        base = target.base_url.rstrip("/")
        owner = httpx.Client(base_url=base, timeout=target.timeout, verify=False, follow_redirects=True, headers=target.auth_headers)
        guest = httpx.Client(base_url=base, timeout=target.timeout, verify=False, follow_redirects=True)

        project_id = self._create_project(owner, target, ctx)
        if project_id:
            self._upload(owner, target, ctx, project_id)
            self._scan_and_wait(owner, target, ctx, project_id)
            self._isolation_check(guest, target, ctx, project_id)
            self._delete_and_refresh(owner, target, ctx, project_id)

        owner.close()
        guest.close()
        return AgentResult(
            agent=self.name,
            events=ctx.events,
            findings=ctx.findings,
            summary={
                "transitions": len([e for e in ctx.events if e.kind == EventKind.TRANSITION]),
                "project_id": project_id,
            },
        )

    def _create_project(self, client, target, ctx) -> Optional[str]:
        ev = ctx.transition(self.name, "owner -> create-project", detail="POST /projects")
        try:
            r = client.post("/projects", json={"name": "medusa-e2e"})
            if r.status_code >= 500:
                self._crash(ctx, self.name, "POST /projects", ev.id, r.status_code)
                return None
            if r.status_code >= 400:
                return None
            pid = (r.json().get("id") if r.headers.get("content-type", "").startswith("application/json") else None)
            return str(pid) if pid else "1"
        except httpx.HTTPError as e:
            ctx.finding(self.name, Severity.HIGH, "Create project failed", str(e), "POST /projects")
            return None

    def _upload(self, client, target, ctx, pid: str) -> None:
        ev = ctx.transition(self.name, "create-project -> upload", detail=f"POST /projects/{pid}/upload")
        try:
            r = client.post(f"/projects/{pid}/upload", files={"file": ("evil.txt", b"<script>alert(1)</script>")})
            if r.status_code >= 500:
                self._crash(ctx, self.name, f"POST /projects/{pid}/upload", ev.id, r.status_code)
        except httpx.HTTPError as e:
            ctx.finding(self.name, Severity.HIGH, "Upload failed", str(e), f"POST /projects/{pid}/upload")

    def _scan_and_wait(self, client, target, ctx, pid: str) -> None:
        ev = ctx.transition(self.name, "upload -> ai-scan", detail=f"POST /projects/{pid}/scan")
        try:
            r = client.post(f"/projects/{pid}/scan")
            if r.status_code >= 500:
                self._crash(ctx, self.name, f"POST /projects/{pid}/scan", ev.id, r.status_code)
                return
        except httpx.HTTPError as e:
            ctx.finding(self.name, Severity.HIGH, "Scan trigger failed", str(e), f"POST /projects/{pid}/scan")
            return

        # poll for worker completion (stateful: job keeps running after request returns)
        for _ in range(10):
            try:
                s = client.get(f"/projects/{pid}")
                if s.status_code == 200 and s.headers.get("content-type", "").startswith("application/json"):
                    if str(s.json().get("status", "")).lower() in ("done", "complete", "finished"):
                        ctx.transition(self.name, "ai-scan -> worker-done", detail="GET /projects/{pid} -> done")
                        return
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        ctx.transition(self.name, "ai-scan -> worker-pending", detail="worker did not finish in poll window")

    def _isolation_check(self, guest, target, ctx, pid: str) -> None:
        ctx.transition(self.name, "guest -> access-owner-data", detail=f"GET /projects/{pid} (no auth)")
        try:
            r = guest.get(f"/projects/{pid}")
            if r.status_code < 400:
                ctx.finding(
                    self.name,
                    Severity.HIGH,
                    title="Cross-user data isolation broken",
                    detail=f"Guest session read owner project {pid} (HTTP {r.status_code}).",
                    location=f"GET /projects/{pid}",
                    cwe="CWE-639",
                    remediation="Scope resources to the authenticated owner; deny cross-tenant access.",
                )
        except httpx.HTTPError:
            pass

    def _delete_and_refresh(self, owner, target, ctx, pid: str) -> None:
        ev = ctx.transition(self.name, "owner -> delete-project", detail=f"DELETE /projects/{pid}")
        try:
            r = owner.delete(f"/projects/{pid}")
            if r.status_code >= 500:
                self._crash(ctx, self.name, f"DELETE /projects/{pid}", ev.id, r.status_code)
                return
        except httpx.HTTPError as e:
            ctx.finding(self.name, Severity.HIGH, "Delete failed", str(e), f"DELETE /projects/{pid}")
            return
        # refresh: deleted resource should be gone
        try:
            r2 = owner.get(f"/projects/{pid}")
            if r2.status_code < 400:
                ctx.finding(
                    self.name,
                    Severity.MEDIUM,
                    title="Deleted resource still accessible",
                    detail=f"GET /projects/{pid} returned {r2.status_code} after deletion.",
                    location=f"GET /projects/{pid}",
                    cwe="CWE-212",
                    remediation="Ensure deletion removes the resource and returns 404 on later reads.",
                )
        except httpx.HTTPError:
            pass

    @staticmethod
    def _crash(ctx, agent, loc, parent, status) -> None:
        ctx.finding(
            scanner=agent,
            severity=Severity.HIGH,
            title=f"Server crash during E2E ({loc})",
            detail=f"HTTP {status} returned during stateful journey.",
            location=loc,
            cwe="CWE-248",
            remediation="Reproduce the journey and fix the unhandled exception.",
        )
