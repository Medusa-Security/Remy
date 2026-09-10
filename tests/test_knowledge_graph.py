"""Tests for the Remy Knowledge Graph and its query engine."""

from __future__ import annotations

from remy.knowledge.graph import KnowledgeGraph
from remy.knowledge import engine
from remy.report.models import Finding, Severity


def _finding(
    fid: str, scanner: str, severity: Severity, file: str, cwe="CWE-79", title="XSS"
):
    return Finding(
        id=fid,
        scanner=scanner,
        severity=severity,
        cwe=cwe,
        file=file,
        line_start=1,
        line_end=2,
        title=title,
        description="unauthenticated route exposed",
        remediation_hint="fix",
        confidence=0.9,
    )


def _build() -> KnowledgeGraph:
    findings = [
        _finding(
            "a1",
            "secrets",
            Severity.CRITICAL,
            "src/app.py",
            cwe="CWE-798",
            title="Hardcoded AWS Key",
        ),
        _finding(
            "b1",
            "api_surface",
            Severity.HIGH,
            "src/app.py",
            cwe="CWE-306",
            title="Unauthenticated route",
        ),
        _finding(
            "c1",
            "sast_python",
            Severity.LOW,
            "src/util.py",
            cwe="CWE-390",
            title="Broad exception",
        ),
    ]
    return KnowledgeGraph.from_findings(findings, "src")


def test_graph_structure():
    g = _build()
    assert g.nodes["file:src/app.py"].kind == "FILE"
    assert g.nodes["finding:a1"].kind == "FINDING"
    assert g.nodes["secret:AWS Key"].kind == "SECRET"
    # file -> finding -> scanner / cwe
    assert g.neighbors("file:src/app.py", "contains")
    assert g.incoming("scanner:secrets", "detected_by")


def test_hotspots_rank_worst_first():
    rows = engine.hotspots(_build())
    assert rows[0][1] == "src/app.py"  # contains CRITICAL + HIGH
    assert rows[0][2] == 0  # CRITICAL rank


def test_secret_exposure():
    rows = engine.secret_exposure(_build())
    assert any("AWS" in r[0] for r in rows)
    assert rows[0][1] == "src/app.py"


def test_unauthenticated_endpoints():
    rows = engine.unauthenticated_endpoints(_build())
    assert any("Unauthenticated" in r[2] for r in rows)


def test_impact_walk():
    g = _build()
    reached = engine.impact(g, "src/app.py")
    kinds = {n.kind for n in reached}
    assert "FINDING" in kinds
    assert "SCANNER" in kinds


def test_node_by_hint_suffix():
    g = _build()
    assert g.node_by_hint("app.py") == "file:src/app.py"
    assert g.node_by_hint("a1") == "finding:a1"
    assert g.node_by_hint("nonexistent") is None
