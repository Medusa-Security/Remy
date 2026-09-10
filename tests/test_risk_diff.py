"""Tests for risk scoring, dependency graph, and PR-diff scope."""

from __future__ import annotations

from pathlib import Path

from remy.knowledge.dependencies import build_dependency_graph, DependencyGraph
from remy.knowledge.risk import score_findings, RiskReport
from remy.report.models import Finding, Severity


def _write_pkg(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("import pkg.b\n")
    (pkg / "b.py").write_text("# leaf module\n")
    (pkg / "c.py").write_text("from pkg.b import thing\nimport pkg.a\n")
    return tmp_path


def test_dependency_graph_finds_importers():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        root = _write_pkg(Path(d))
        g = build_dependency_graph(root)
        b = str((root / "pkg" / "b.py").resolve())
        assert b in g.importers
        importers = {Path(p).name for p in g.importers[b]}
        assert {"a.py", "c.py"} == importers


def test_dependents_are_transitive():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        root = _write_pkg(Path(d))
        g = build_dependency_graph(root)
        b = str((root / "pkg" / "b.py").resolve())
        deps = {Path(p).name for p in g.dependents(b)}
        assert deps == {"a.py", "c.py"}


def _f(fid, scanner, severity, file):
    return Finding(
        id=fid, scanner=scanner, severity=severity, cwe=None, file=file,
        line_start=1, line_end=1, title="X", description="d",
        remediation_hint="", confidence=0.9,
    )


def test_risk_ranks_public_critical_above_isolated_critical():
    g = DependencyGraph()
    # isolated.py has no importers; shared.py is imported by 10 files
    for i in range(10):
        g.importers.setdefault(str(Path(f"/x/dep{i}.py")), set()).add("/x/shared.py")

    findings = [
        _f("iso", "sast_python", Severity.CRITICAL, "/x/isolated.py"),
        _f("pub", "api_surface", Severity.CRITICAL, "/x/shared.py"),
    ]
    report = score_findings(findings, g)
    assert isinstance(report, RiskReport)
    # public + highly imported critical must outrank isolated critical
    assert report.items[0].finding_id == "pub"
    assert report.items[0].score > report.items[1].score


def test_risk_blast_radius_amplifies_score():
    g = DependencyGraph()
    for i in range(20):
        g.importers.setdefault("/x/core.py", set()).add(f"/x/d{i}.py")
    f = _f("c", "sast_python", Severity.HIGH, "/x/core.py")
    item = score_findings([f], g).items[0]
    assert item.blast_radius == 20
    # HIGH (8) * (1+0.2) * (1+0.1*20) = 8 * 1.2 * 3 = 28.8
    assert item.score == 28.8


def test_pr_scope_expands_changed_with_dependents():
    g = DependencyGraph()
    g.importers.setdefault("/x/lib.py", set()).add("/x/app.py")
    g.importers.setdefault("/x/app.py", set()).add("/x/main.py")
    scope = {"/x/lib.py"} | g.dependents("/x/lib.py")
    assert scope == {"/x/lib.py", "/x/app.py", "/x/main.py"}
