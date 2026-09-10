"""Builds the runtime Event Graph from agent events + findings.

The Event Graph is the *dynamic* counterpart to the static Knowledge Graph
built from SAST findings. Together they let Remy "understand the architecture":
static code nodes (file/finding) on one side, live runtime nodes (page/
endpoint/service/span) on the other, joined by the same edge vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


from .events import Event, EventKind


@dataclass
class GNode:
    id: str
    kind: str  # PAGE | ENDPOINT | SERVICE | FINDING | USER | STATE
    label: str
    attrs: dict = field(default_factory=dict)


@dataclass
class GEdge:
    source: str
    target: str
    relation: (
        str  # navigate_to | requests | calls | results_in | triggers | transitions
    )


_SERVICE_HINTS = (
    "redis",
    "celery",
    "postgres",
    "mysql",
    "openai",
    "express",
    "worker",
    "queue",
    "db",
)


def _service_name(target: str) -> Optional[str]:
    low = target.lower()
    for s in _SERVICE_HINTS:
        if s in low:
            return s
    return None


class RuntimeGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, GNode] = {}
        self.edges: list[GEdge] = []

    def add_node(self, node: GNode) -> GNode:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
        return self.nodes[node.id]

    def add_edge(self, source: str, target: str, relation: str) -> None:
        if source in self.nodes and target in self.nodes:
            self.edges.append(GEdge(source, target, relation))

    def neighbors(self, node_id: str, relation: Optional[str] = None) -> list[GNode]:
        return [
            self.nodes[e.target]
            for e in self.edges
            if e.source == node_id and (relation is None or e.relation == relation)
        ]

    def reachable(self, node_id: str, max_depth: int = 4) -> list[GNode]:
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


def build(events: list[Event], findings: list) -> RuntimeGraph:
    """Convert raw agent events + findings into a queryable runtime graph."""
    g = RuntimeGraph()

    for ev in events:
        if ev.kind == EventKind.NAVIGATE:
            page_id = f"page:{ev.target}"
            g.add_node(GNode(page_id, "PAGE", ev.target))
        elif ev.kind == EventKind.REQUEST:
            ep_id = f"endpoint:{ev.target}"
            g.add_node(GNode(ep_id, "ENDPOINT", ev.target))
            svc = _service_name(ev.target)
            if svc:
                svc_id = f"service:{svc}"
                g.add_node(GNode(svc_id, "SERVICE", svc))
                g.add_edge(ep_id, svc_id, "calls")
            # link request to its parent (e.g. a click navigated there)
            if ev.parent_id:
                parent = _find(events, ev.parent_id)
                if parent and parent.kind in (EventKind.CLICK, EventKind.NAVIGATE):
                    g.add_edge(f"page:{parent.target}", ep_id, "requests")
        elif ev.kind == EventKind.RESPONSE:
            ep_id = f"endpoint:{ev.target}"
            g.add_node(GNode(ep_id, "ENDPOINT", ev.target))
        elif ev.kind in (EventKind.DB_QUERY, EventKind.QUEUE):
            svc = _service_name(ev.target) or ev.target.split(":")[0]
            svc_id = f"service:{svc}"
            g.add_node(GNode(svc_id, "SERVICE", svc))
            ep_id = f"endpoint:{ev.target}"
            if ep_id in g.nodes:
                g.add_edge(ep_id, svc_id, "triggers")
        elif ev.kind == EventKind.TRANSITION:
            g.add_node(GNode(f"state:{ev.target}", "STATE", ev.target))

    for f in findings:
        fid = f"finding:{f.id}"
        g.add_node(
            GNode(
                fid,
                "FINDING",
                f.title,
                {
                    "severity": (
                        f.severity.value
                        if hasattr(f.severity, "value")
                        else str(f.severity)
                    ),
                    "cwe": f.cwe,
                },
            )
        )
        loc = f.file
        # attach the finding to the runtime node it occurred at (endpoint or page)
        if f"endpoint:{loc}" in g.nodes:
            g.add_edge(f"endpoint:{loc}", fid, "results_in")
        elif f"page:{loc}" in g.nodes:
            g.add_edge(f"page:{loc}", fid, "results_in")

    return g


def _find(events: list[Event], event_id: str) -> Optional[Event]:
    for ev in events:
        if ev.id == event_id:
            return ev
    return None


def services(g: RuntimeGraph) -> list[GNode]:
    return [n for n in g.nodes.values() if n.kind == "SERVICE"]
