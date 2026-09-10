"""Query primitives over the Remy Knowledge Graph.

These answer the questions from the Medusa vision using *static* evidence
today (files, findings, scanners, CWEs, secrets) and remain valid once the
dynamic agents contribute runtime spans — the graph shape is the same.
"""

from __future__ import annotations

from .graph import KnowledgeGraph, SEVERITY_RANK

_UNSAFE_HINTS = (
    "unauthenticated",
    "no auth",
    "exposed route",
    "missing auth",
    "publicly accessible",
    "missing rate limit",
)


def summary(g: KnowledgeGraph) -> dict:
    counts: dict[str, int] = {}
    for n in g.nodes.values():
        counts[n.kind] = counts.get(n.kind, 0) + 1
    return {
        "nodes": len(g.nodes),
        "edges": len(g.edges),
        "files": counts.get("FILE", 0),
        "findings": counts.get("FINDING", 0),
        "scanners": counts.get("SCANNER", 0),
        "cwes": counts.get("CWE", 0),
        "secrets": counts.get("SECRET", 0),
    }


def hotspots(g: KnowledgeGraph) -> list[tuple[str, str, int, int]]:
    """Files ranked by worst severity (then finding count) — the 'most at risk' proxy."""
    rows: list[tuple[str, str, int, int]] = []
    for nid, n in g.nodes.items():
        if n.kind != "FILE":
            continue
        findings = g.neighbors(nid, "contains")
        if not findings:
            continue
        worst = min(
            SEVERITY_RANK.get(f.attrs.get("severity", "INFO"), 4) for f in findings
        )
        rows.append((nid, n.label, worst, len(findings)))
    rows.sort(key=lambda r: (r[2], -r[3]))
    return rows


def by_scanner(g: KnowledgeGraph) -> list[tuple[str, int]]:
    rows = []
    for n in g.nodes.values():
        if n.kind == "SCANNER":
            rows.append((n.label, len(g.incoming(n.id, "detected_by"))))
    return sorted(rows, key=lambda r: -r[1])


def unauthenticated_endpoints(g: KnowledgeGraph) -> list[tuple[str, str, str]]:
    """Findings that read as exposed / unauthenticated routes."""
    rows = []
    for n in g.nodes.values():
        if n.kind != "FINDING":
            continue
        desc = (n.attrs.get("description") or "").lower()
        sev = n.attrs.get("severity", "INFO")
        if any(h in desc for h in _UNSAFE_HINTS):
            file_node = g.incoming(n.id, "contains")
            loc = file_node[0].label if file_node else "?"
            rows.append((sev, loc, n.label))
    return sorted(rows, key=lambda r: SEVERITY_RANK.get(r[0], 4))


def secret_exposure(g: KnowledgeGraph) -> list[tuple[str, str, str]]:
    """Each secret category, the finding, and the file that leaks it."""
    rows = []
    for s in g.nodes.values():
        if s.kind != "SECRET":
            continue
        for finding in g.incoming(s.id, "exposes"):
            file_node = g.incoming(finding.id, "contains")
            loc = file_node[0].label if file_node else "?"
            rows.append((s.label, loc, finding.label))
    return sorted(rows, key=lambda r: r[0])


def impact(g: KnowledgeGraph, node_hint: str, max_depth: int = 2) -> list:
    """Return everything reachable from a file path or finding id.

    This is the generic 'what breaks if I remove X' primitive — once runtime
    agents attach spans, the same walk surfaces downstream request flows.
    """
    nid = g.node_by_hint(node_hint)
    if nid is None:
        return []
    return g.reachable(nid, max_depth=max_depth)
