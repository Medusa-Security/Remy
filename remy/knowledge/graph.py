"""Remy Knowledge Graph — turns scan findings into a queryable graph.

This is the foundation of Remy's "understands your architecture" vision.
Every finding becomes a node wired to the file, scanner, CWE, and secret
that produced it. The dynamic agents from the Medusa architecture
(browser / API / security) can later attach runtime traces, request flows,
and event edges to the very same graph, so root-cause and impact queries
work uniformly across static and runtime evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Node:
    id: str
    kind: str  # FILE | FINDING | SCANNER | CWE | SECRET
    label: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    relation: str  # contains | detected_by | classified_as | exposes


def _severity_value(sev) -> str:
    if hasattr(sev, "value"):
        return sev.value
    return str(sev)


def _secret_type(title: str) -> str:
    """Normalize a secrets-scanner title into a stable secret category."""
    s = title or ""
    for prefix in ("Hardcoded ", "Hard-coded ", "Leaked ", "Exposed "):
        if s.startswith(prefix):
            s = s[len(prefix) :]
    return s.strip().rstrip(".") or "Unknown Secret"


class KnowledgeGraph:
    """A small, dependency-free directed graph over scan evidence."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.target_path: str = ""

    # ── mutation ───────────────────────────────────────────────────────────
    def add_node(self, node: Node) -> Node:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
        return self.nodes[node.id]

    def add_edge(self, source: str, target: str, relation: str) -> None:
        if source in self.nodes and target in self.nodes:
            self.edges.append(Edge(source, target, relation))

    # ── construction ───────────────────────────────────────────────────────
    @classmethod
    def from_findings(cls, findings, target_path: str = "") -> "KnowledgeGraph":
        g = cls()
        g.target_path = target_path
        for f in findings:
            file_id = f"file:{f.file}"
            g.add_node(Node(file_id, "FILE", f.file, {"path": f.file}))

            finding_id = f"finding:{f.id}"
            g.add_node(
                Node(
                    finding_id,
                    "FINDING",
                    f.title,
                    {
                        "severity": _severity_value(f.severity),
                        "cwe": f.cwe,
                        "line": f.line_start,
                        "description": f.description,
                    },
                )
            )
            g.add_edge(file_id, finding_id, "contains")

            scanner_id = f"scanner:{f.scanner}"
            g.add_node(Node(scanner_id, "SCANNER", f.scanner))
            g.add_edge(finding_id, scanner_id, "detected_by")

            if f.cwe:
                cwe_id = f"cwe:{f.cwe}"
                g.add_node(Node(cwe_id, "CWE", f.cwe))
                g.add_edge(finding_id, cwe_id, "classified_as")

            if f.scanner == "secrets":
                secret_id = f"secret:{_secret_type(f.title)}"
                g.add_node(Node(secret_id, "SECRET", _secret_type(f.title)))
                g.add_edge(finding_id, secret_id, "exposes")
        return g

    # ── traversal ──────────────────────────────────────────────────────────
    def neighbors(self, node_id: str, relation: str | None = None) -> list[Node]:
        return [
            self.nodes[e.target]
            for e in self.edges
            if e.source == node_id and (relation is None or e.relation == relation)
        ]

    def incoming(self, node_id: str, relation: str | None = None) -> list[Node]:
        return [
            self.nodes[e.source]
            for e in self.edges
            if e.target == node_id and (relation is None or e.relation == relation)
        ]

    def reachable(self, node_id: str, max_depth: int = 2) -> list[Node]:
        """Breadth-first walk of the subgraph downstream of ``node_id``."""
        seen: set[str] = set()
        frontier = [node_id]
        for _ in range(max_depth):
            nxt: list[str] = []
            for nid in frontier:
                for e in self.edges:
                    if e.source == nid and e.target not in seen:
                        seen.add(e.target)
                        nxt.append(e.target)
            frontier = nxt
        return [self.nodes[i] for i in seen if i != node_id]

    def node_by_hint(self, hint: str) -> str | None:
        """Resolve a user-supplied file path or finding id to a graph node id."""
        hint = hint.strip()
        if hint in self.nodes:
            return hint
        if f"file:{hint}" in self.nodes:
            return f"file:{hint}"
        if f"finding:{hint}" in self.nodes:
            return f"finding:{hint}"
        # case-insensitive file path match (full path or trailing suffix)
        low = hint.lower().replace("/", "\\")
        for nid, n in self.nodes.items():
            if n.kind == "FILE":
                label = n.label.lower().replace("/", "\\")
                if label == low or label.endswith("\\" + low) or label.endswith(low):
                    return nid
        return None
