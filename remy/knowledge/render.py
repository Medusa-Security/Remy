"""Rich rendering for the Remy Knowledge Graph CLI."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from .graph import KnowledgeGraph, SEVERITY_RANK
from . import engine

_SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}


def render_tree(console: Console, g: KnowledgeGraph) -> None:
    tree = Tree(f"[bold color(220)]Remy Knowledge Graph[/]  [dim]{g.target_path}[/]")
    file_nodes = {nid: n for nid, n in g.nodes.items() if n.kind == "FILE"}
    for nid, n in sorted(file_nodes.items(), key=lambda kv: kv[1].label):
        findings = g.neighbors(nid, "contains")
        if not findings:
            continue
        branch = tree.add(f"[bold]{n.label}[/]")
        for f in sorted(
            findings,
            key=lambda x: SEVERITY_RANK.get(x.attrs.get("severity", "INFO"), 4),
        ):
            sev = f.attrs.get("severity", "INFO")
            cwe = f" [dim]{f.attrs.get('cwe')}[/]" if f.attrs.get("cwe") else ""
            branch.add(f"[{_SEV_COLOR.get(sev, 'white')}]{sev}[/] {f.label}{cwe}")
    console.print(tree)


def render_summary(console: Console, g: KnowledgeGraph) -> None:
    s = engine.summary(g)
    t = Table(title="Knowledge Graph — Summary", show_header=False, box=None)
    t.add_column(style="bold")
    t.add_column()
    for label, val in [
        ("Nodes", s["nodes"]),
        ("Edges", s["edges"]),
        ("Files", s["files"]),
        ("Findings", s["findings"]),
        ("Scanners", s["scanners"]),
        ("CWE classes", s["cwes"]),
        ("Secret types", s["secrets"]),
    ]:
        t.add_row(label, str(val))
    console.print(t)


def render_hotspots(console: Console, g: KnowledgeGraph) -> None:
    rows = engine.hotspots(g)
    t = Table(title="Risk Hotspots (worst file first)", box=None)
    t.add_column("#", style="dim", justify="right")
    t.add_column("File")
    t.add_column("Worst", justify="center")
    t.add_column("Findings", justify="right")
    for i, (_nid, label, worst, count) in enumerate(rows, 1):
        sev = [k for k, v in SEVERITY_RANK.items() if v == worst][0]
        t.add_row(
            str(i), label, f"[{_SEV_COLOR.get(sev, 'white')}]{sev}[/]", str(count)
        )
    console.print(t)


def render_by_scanner(console: Console, g: KnowledgeGraph) -> None:
    rows = engine.by_scanner(g)
    t = Table(title="Findings by Scanner", box=None)
    t.add_column("Scanner")
    t.add_column("Findings", justify="right")
    for name, count in rows:
        t.add_row(name, str(count))
    console.print(t)


def render_unauthenticated(console: Console, g: KnowledgeGraph) -> None:
    rows = engine.unauthenticated_endpoints(g)
    if not rows:
        console.print(
            "[green]OK:[/green] No obviously exposed / unauthenticated routes detected."
        )
        return
    t = Table(title="Potential Exposed Endpoints", box=None)
    t.add_column("Severity", justify="center")
    t.add_column("File")
    t.add_column("Finding")
    for sev, loc, title in rows:
        t.add_row(f"[{_SEV_COLOR.get(sev, 'white')}]{sev}[/]", loc, title)
    console.print(t)


def render_secrets(console: Console, g: KnowledgeGraph) -> None:
    rows = engine.secret_exposure(g)
    if not rows:
        console.print("[green]OK:[/green] No hardcoded secrets detected.")
        return
    t = Table(title="Secret Exposure", box=None)
    t.add_column("Secret type")
    t.add_column("File")
    t.add_column("Finding")
    for stype, loc, title in rows:
        t.add_row(stype, loc, title)
    console.print(t)


def render_impact(console: Console, g: KnowledgeGraph, hint: str) -> None:
    nid = g.node_by_hint(hint)
    if nid is None:
        console.print(f"[yellow]No node matches '{hint}'.[/yellow]")
        return
    reached = engine.impact(g, hint)
    root = g.nodes[nid]
    console.print(
        f"[bold color(220)]Impact of[/] [bold]{root.label}[/] "
        f"[dim]({root.kind})[/] -> [bold]{len(reached)}[/] reachable node(s)\n"
    )
    for n in reached:
        detail = ""
        if n.kind == "FINDING":
            detail = f" [{_SEV_COLOR.get(n.attrs.get('severity','INFO'),'white')}]{n.attrs.get('severity')}[/]"
        console.print(f"  - [bold]{n.kind}[/] {n.label}{detail}")


def render_risk(console: Console, report) -> None:
    from .risk import RiskReport

    if not isinstance(report, RiskReport):
        return
    if not report.items:
        console.print("[green]OK:[/green] No findings to score.")
        return
    t = Table(title="Risk Ranking (severity x reachability x blast-radius)", box=None)
    t.add_column("#", justify="right", style="dim")
    t.add_column("Risk", justify="center")
    t.add_column("Score", justify="right")
    t.add_column("Sev", justify="center")
    t.add_column("Reach", justify="right")
    t.add_column("Blast", justify="right")
    t.add_column("Finding")
    t.add_column("Where")
    for i, item in enumerate(report.items[:25], 1):
        color = {
            "CRITICAL-RISK": "bold red",
            "HIGH-RISK": "red",
            "MEDIUM-RISK": "yellow",
            "LOW-RISK": "cyan",
        }.get(item.rating, "white")
        t.add_row(
            str(i),
            f"[{color}]{item.rating}[/]",
            f"{item.score:g}",
            item.severity,
            f"{item.reachability:g}",
            str(item.blast_radius),
            item.title,
            item.location,
        )
    console.print(t)
