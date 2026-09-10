"""Tests for the Medusa dynamic-testing subsystem.

Covers pure-logic units (graph builder, root cause, regression) and one
real end-to-end orchestrated run against an in-process mock server so the
API fuzzer, stateful E2E, and runtime tracer exercise against live HTTP.
"""

from __future__ import annotations

import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from remy.medusa.events import Event, EventKind, EventStatus
from remy.medusa.graph_builder import build, RuntimeGraph
from remy.medusa.root_cause import chain_for, explain
from remy.medusa.regression import Baseline, RegressionStore
from remy.medusa import MedusaOrchestrator, MedusaTarget


# ── pure logic ────────────────────────────────────────────────────────────────


def test_graph_builder_links_endpoint_to_finding():
    ev = [
        Event.make(EventKind.REQUEST, "api", "POST /scan"),
        Event.make(EventKind.EXCEPTION, "api", "POST /scan", parent_id=None),
    ]
    ev[1].parent_id = ev[0].id
    findings = [
        type("_F", (), {
            "id": "api:0", "scanner": "api", "title": "crash",
            "severity": type("S", (), {"value": "HIGH"})(), "cwe": "CWE-248",
            "file": "POST /scan",
        })()
    ]
    g = build(ev, findings)
    assert "endpoint:POST /scan" in g.nodes
    assert any(n.kind == "FINDING" for n in g.nodes.values())
    # finding should be attached to its endpoint
    assert g.neighbors("endpoint:POST /scan", "results_in")


def test_root_cause_chain():
    click = Event.make(EventKind.CLICK, "browser", "Scan button")
    req = Event.make(EventKind.REQUEST, "browser", "POST /scan", parent_id=click.id)
    exc = Event.make(EventKind.EXCEPTION, "browser", "POST /scan", parent_id=req.id, status=EventStatus.ERROR)
    chain = chain_for(exc.id, [click, req, exc])
    assert [e.kind for e in chain] == [EventKind.CLICK, EventKind.REQUEST, EventKind.EXCEPTION]
    rc = explain(exc.id, [click, req, exc])
    assert "Scan button" in rc.explanation


def test_regression_detects_new_critical():
    store = RegressionStore(root=Path(".pytest_baselines"))
    prev = Baseline(target="http://x", finding_counts={"CRITICAL": 0}, p95_latency_ms=100.0, error_count=0)
    store.save(prev)
    cur = Baseline(target="http://x", finding_counts={"CRITICAL": 1}, p95_latency_ms=100.0, error_count=0)
    rep = store.compare(cur, [])
    assert rep.has_regression
    assert any("new-critical" in f for f in rep.flags)


def test_regression_latency_flag():
    store = RegressionStore(root=Path(".pytest_baselines"))
    store.save(Baseline(target="http://y", p95_latency_ms=100.0))
    cur = Baseline(target="http://y", p95_latency_ms=400.0)
    rep = store.compare(cur, [])
    assert rep.latency_regression_pct == 300.0
    assert any("latency-regression" in f for f in rep.flags)


# ── integration: live mock server ──────────────────────────────────────────────


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"{}", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def _auth(self):
        return bool(self.headers.get("Authorization"))

    def do_GET(self):
        if self.path == "/dashboard" and not self._auth():
            return self._send(401, b'{"error":"no auth"}')
        if self.path == "/admin" and not self._auth():
            return self._send(401)
        if self.path == "/projects/1":
            return self._send(404, b'{"error":"gone"}')
        return self._send(200, b'{"ok":1}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if self.path == "/login":
            return self._send(200, b'{"token":"t"}')
        if self.path == "/projects":
            return self._send(200, b'{"id":1}')
        if self.path == "/projects/1/upload":
            return self._send(200, b'{"ok":1}')
        if self.path == "/projects/1/scan":
            return self._send(500, b'{"error":"boom"}')
        if self.path == "/api/scan":
            if b"DROP TABLE" in body or len(body) > 1000:
                return self._send(500, b'{"error":"crash"}')
            return self._send(200, b'{"ok":1}')
        return self._send(200, b'{"ok":1}')

    def do_DELETE(self):
        if self.path == "/project/1" and not self._auth():
            return self._send(401)
        return self._send(200, b'{"ok":1}')

    def log_message(self, *a):
        pass


def _start_server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


_SPEC = {
    "paths": {
        "/api/scan": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"properties": {"email": {}}}}
                    }
                }
            }
        }
    }
}


def test_medusa_orchestrated_run():
    srv, port = _start_server()
    try:
        target = MedusaTarget(base_url=f"http://127.0.0.1:{port}", auth_token="t", openapi_spec=_SPEC)
        orch = MedusaOrchestrator(baseline_dir=".pytest_baselines")
        report = orch.run(target, agents=["api", "e2e", "workflow", "trace"])

        # findings came from the fuzzer (crash + auth bypass) and e2e (scan 500)
        assert report.findings, "expected findings from the run"
        titles = " ".join(f.title for f in report.findings)
        assert "crash" in titles.lower() or "auth bypass" in titles.lower()

        # runtime graph built
        assert isinstance(report.graph, RuntimeGraph)
        assert any(n.kind == "ENDPOINT" for n in report.graph.nodes.values())

        # root cause computed for the failing scan
        assert report.root_causes, "expected at least one root cause"

        # regression baseline saved + compared
        assert report.regression is not None
    finally:
        srv.shutdown()
