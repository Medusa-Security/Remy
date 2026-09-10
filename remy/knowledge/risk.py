"""Risk scoring — severity x reachability x blast-radius.

A CRITICAL behind auth is not the same as a CRITICAL on a public, unauthenticated
endpoint that 40 other modules depend on. This engine combines three factors
into one comparable score so Remy can tell you what to fix *first*:

* **severity** — base weight from the finding's severity.
* **reachability** — how exposed the finding is (public/unauthenticated surface
  scores high; internal/secret leakage scores medium).
* **blast radius** — how many files transitively import the affected file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from remy.knowledge.dependencies import DependencyGraph



SEVERITY_WEIGHT = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 1.0,
}

# Scanners whose findings describe the *public* attack surface score higher.
_PUBLIC_SCANNERS = {"api_surface", "auth_bypass"}


@dataclass
class RiskItem:
    finding_id: str
    title: str
    severity: str
    location: str
    scanner: str
    reachability: float
    blast_radius: int
    score: float

    @property
    def rating(self) -> str:
        if self.score >= 40:
            return "CRITICAL-RISK"
        if self.score >= 20:
            return "HIGH-RISK"
        if self.score >= 10:
            return "MEDIUM-RISK"
        return "LOW-RISK"


@dataclass
class RiskReport:
    items: list[RiskItem] = field(default_factory=list)

    @property
    def top(self, n: int = 10) -> list[RiskItem]:
        return sorted(self.items, key=lambda i: -i.score)[:n]


def _severity_value(sev) -> str:
    return sev.value if hasattr(sev, "value") else str(sev)


def _reachability(scanner: str, location: str, public_endpoints: set[str]) -> float:
    if scanner in _PUBLIC_SCANNERS:
        return 0.8
    if location in public_endpoints:
        return 0.8
    if scanner == "secrets":
        return 0.5
    return 0.2


def score_findings(
    findings: list,
    dep_graph: DependencyGraph | None = None,
    public_endpoints: set[str] | None = None,
) -> RiskReport:
    public_endpoints = public_endpoints or set()
    items: list[RiskItem] = []

    for f in findings:
        sev = _severity_value(f.severity)
        base = SEVERITY_WEIGHT.get(sev, 1.0)
        reach = _reachability(f.scanner, f.file, public_endpoints)

        blast = 0
        if dep_graph is not None:
            blast = len(dep_graph.dependents(f.file))

        # compounded, not summed: severity is amplified by exposure and spread
        score = base * (1.0 + reach) * (1.0 + 0.1 * blast)
        items.append(
            RiskItem(
                finding_id=f.id,
                title=f.title,
                severity=sev,
                location=f.file,
                scanner=f.scanner,
                reachability=round(reach, 2),
                blast_radius=blast,
                score=round(score, 2),
            )
        )

    items.sort(key=lambda i: -i.score)
    return RiskReport(items=items)
