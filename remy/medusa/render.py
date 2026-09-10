"""Rich rendering for the Medusa orchestrated run."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from .orchestrator import MedusaReport
from .graph_builder import RuntimeGraph
from .regression import RegressionReport


def _sev_color(sev: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim white",
    }.get(sev, "white")


def render_report(console: Console, report: MedusaReport) -> None:
    console.print(
        f"[bold color(220)]Medusa Run[/] [dim]{report.run_id}[/] -> "
        f"[bold]{report.target}[/]  ({report.duration_seconds}s)"
    )

    for name, reason in report.skipped:
        console.print(f"[dim yellow]skipped {name}: {reason}[/dim yellow]")

    render_findings(console, report)
    render_graph(console, report.graph)
    render_root_causes(console, report)
    if report.regression:
        render_regression(console, report.regression)


def render_findings(console: Console, report: MedusaReport) -> None:
    findings = report.findings
    if not findings:
        console.print("[green]OK:[/green] No findings from Medusa agents.")
        return
    t = Table(title="Medusa Findings", box=None)
    t.add_column("#", justify="right", style="dim")
    t.add_column("Sev", justify="center")
    t.add_column("Agent")
    t.add_column("Finding")
    t.add_column("Where")
    for i, f in enumerate(findings, 1):
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        t.add_row(
            str(i),
            f"[{_sev_color(sev)}]{sev}[/]",
            f.scanner,
            f.title,
            f.file,
        )
    console.print(t)


def render_graph(console: Console, graph: RuntimeGraph | None) -> None:
    if graph is None:
        return
    tree = Tree("[bold color(220)]Runtime Graph[/]")
    endpoints = {n.id: n for n in graph.nodes.values() if n.kind == "ENDPOINT"}
    services = {n.id: n for n in graph.nodes.values() if n.kind == "SERVICE"}
    findings = {n.id: n for n in graph.nodes.values() if n.kind == "FINDING"}

    for nid, n in sorted(endpoints.items(), key=lambda kv: kv[1].label):
        branch = tree.add(f"[bold]{n.label}[/]")
        for svc in graph.neighbors(nid, "calls"):
            branch.add(f"[cyan]calls[/] {svc.label}")
        for trig in graph.neighbors(nid, "triggers"):
            branch.add(f"[cyan]triggers[/] {trig.label}")
        for f in graph.neighbors(nid, "results_in"):
            branch.add(f"[{_sev_color(f.attrs.get('severity', 'INFO'))}]{f.label}[/]")

    if services:
        svc_branch = tree.add("[bold]Services[/]")
        for nid, n in services.items():
            svc_branch.add(n.label)
    if findings and not endpoints:
        for nid, n in findings.items():
            tree.add(f"[{_sev_color(n.attrs.get('severity', 'INFO'))}]{n.label}[/]")

    console.print(tree)


def render_root_causes(console: Console, report: MedusaReport) -> None:
    if not report.root_causes:
        return
    console.print(f"\n[bold]Root Cause Analysis[/] ({len(report.root_causes)} failure(s))")
    for rc in report.root_causes:
        console.print(f"  [red]{rc.failure_id}[/] {rc.explanation}")


def render_regression(console: Console, reg: RegressionReport) -> None:
    console.print("\n[bold]Regression (baseline compare)[/]")
    if reg.previous is None:
        console.print("  [dim]First run — baseline saved.[/dim]")
        return
    if reg.has_regression:
        for flag in reg.flags:
            console.print(f"  [red]FLAG[/] {flag}")
    else:
        console.print("  [green]OK:[/green] No regressions vs baseline.")
