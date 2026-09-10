"""Agent 3 — API Fuzzing.

Being deliberately evil to the API. Instead of sending the happy-path payload,
we fire malformed inputs (null, arrays, giant unicode, path traversal, SQLi)
at every discovered endpoint and watch for the things that should never happen:
5xx crashes, auth bypass, secret/stack-trace leaks, and suspiciously permissive
validation (200 OK for an obvious injection).
"""

from __future__ import annotations

import time

import httpx

from ..agents import AgentContext, BaseAgent
from ..events import AgentResult, EventKind
from ..target import MedusaTarget
from remy.report.models import Severity


_FUZZ_SCALARS = [
    None,
    [],
    {},
    0,
    -1,
    True,
    False,
    "",
    "a" * 50000,
    "💀" * 5000,
    "../../../../etc/passwd",
    "'; DROP TABLE users;--",
    "<script>alert(1)</script>",
    "{'$gt': ''}",
    "null\0byte",
]

_SENSITIVE_PATH_HINTS = ("login", "account", "admin", "profile", "me", "scan", "create", "delete", "user", "token")

_LEAK_SIGNATURES = (
    "traceback (most recent call last)",
    "sql syntax",
    "sqlstate",
    "stack trace",
    "permission denied",
    "secret",
    "api_key",
    "password",
    "stacktrace",
)


def _is_sensitive(path: str) -> bool:
    low = path.lower()
    return any(h in low for h in _SENSITIVE_PATH_HINTS)


class ApiFuzzerAgent(BaseAgent):
    name = "api-fuzzer"

    def run(self, target: MedusaTarget, ctx: AgentContext) -> AgentResult:
        endpoints = target.endpoints_from_spec() or [{"method": "GET", "path": "/", "body_props": []}]
        errors = 0
        latencies: list[float] = []

        with httpx.Client(
            base_url=target.base_url.rstrip("/"),
            timeout=target.timeout,
            headers=target.auth_headers,
            cookies=target.cookies,
            verify=False,
            follow_redirects=True,
        ) as client:
            for ep in endpoints:
                method = ep["method"]
                path = ep["path"]
                body_props = ep.get("body_props", [])
                latencies.append(
                    self._fuzz_endpoint(client, target, ctx, method, path, body_props)
                )
                # auth-bypass probe: hit a sensitive path with NO credentials
                if _is_sensitive(path) and target.auth_token:
                    self._auth_bypass_probe(client, target, ctx, method, path)
                errors += sum(
                    1 for e in ctx.events if e.kind == EventKind.EXCEPTION and e.target.endswith(path)
                )

        p95 = sorted(latencies)[int(len(latencies) * 0.95) - 1] if latencies else 0.0
        return AgentResult(
            agent=self.name,
            events=ctx.events,
            findings=ctx.findings,
            summary={
                "endpoints": len(endpoints),
                "requests": len([e for e in ctx.events if e.kind == EventKind.REQUEST]),
                "p95_latency_ms": round(p95, 1),
                "errors": errors,
            },
        )

    def _fuzz_endpoint(self, client, target, ctx, method, path, body_props) -> float:
        best_latency = 0.0
        for value in _FUZZ_SCALARS:
            payload = {p: value for p in body_props} if body_props else None
            req_ev = ctx.request(self.name, f"{method} {path}", detail=f"payload={value!r}")
            t0 = time.perf_counter()
            try:
                if method == "GET":
                    r = client.get(path, params={"q": value} if value is not None else None)
                else:
                    r = client.request(method, path, json=payload)
                dt = (time.perf_counter() - t0) * 1000
                best_latency = max(best_latency, dt)
                ctx.response(self.name, f"{method} {path}", parent=req_ev.id, detail=f"{r.status_code}", duration_ms=dt)

                if r.status_code >= 500:
                    ctx.exception(
                        self.name,
                        f"{method} {path}",
                        parent=req_ev.id,
                        detail=f"HTTP {r.status_code} on malformed input {value!r}",
                    )
                    ctx.finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title=f"Server crash on fuzzed input ({method} {path})",
                        detail=f"Status {r.status_code} returned for payload {value!r}. "
                        "Unhandled input likely causes an unhandled exception server-side.",
                        location=f"{method} {path}",
                        cwe="CWE-248",
                        remediation="Validate and reject malformed input at the boundary; return 400, not 500.",
                    )
                elif self._looks_leaky(r):
                    ctx.finding(
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        title=f"Possible info leak ({method} {path})",
                        detail="Response body contains a stack trace, SQL error, or secret-like material.",
                        location=f"{method} {path}",
                        cwe="CWE-209",
                        remediation="Return generic error messages; never leak internals to clients.",
                    )
                elif method != "GET" and r.status_code == 200 and _looks_injection(value):
                    ctx.finding(
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        title=f"Permissive validation ({method} {path})",
                        detail=f"Server accepted an obvious injection payload ({value!r}) with 200 OK.",
                        location=f"{method} {path}",
                        cwe="CWE-20",
                        remediation="Reject injection patterns; validate types and ranges strictly.",
                    )
            except httpx.HTTPError as e:
                dt = (time.perf_counter() - t0) * 1000
                best_latency = max(best_latency, dt)
                ctx.exception(
                    self.name,
                    f"{method} {path}",
                    parent=req_ev.id,
                    detail=f"{type(e).__name__}: {e}",
                    duration_ms=dt,
                )
        return best_latency

    def _auth_bypass_probe(self, client, target, ctx, method, path) -> None:
        req_ev = ctx.request(self.name, f"{method} {path} [no-auth]", detail="auth-bypass probe")
        try:
            r = client.request(method, path, headers={}) if method == "GET" else client.request(method, path, headers={}, json={})
            ctx.response(self.name, f"{method} {path}", parent=req_ev.id, detail=f"{r.status_code}")
            if r.status_code < 400:
                ctx.finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title=f"Possible auth bypass ({method} {path})",
                    detail=f"Sensitive endpoint returned {r.status_code} without any credentials.",
                    location=f"{method} {path}",
                    cwe="CWE-306",
                    remediation="Enforce authentication/authorization on every sensitive route.",
                )
        except httpx.HTTPError:
            pass

    @staticmethod
    def _looks_leaky(r: httpx.Response) -> bool:
        try:
            body = r.text.lower()
        except Exception:
            return False
        return any(sig in body for sig in _LEAK_SIGNATURES)

    def available(self) -> bool:
        return True


def _looks_injection(value) -> bool:
    if not isinstance(value, str):
        return False
    return any(t in value for t in ("DROP TABLE", "<script", "../", "$gt", " OR ", "';"))
