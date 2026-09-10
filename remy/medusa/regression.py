"""Regression detection: every run becomes a baseline; the next run is compared.

Stores a compact summary of each Medusa run keyed by target URL under
``.remy/medusa/baselines/``. On a subsequent run we diff the two summaries and
flag the things that matter: new findings, latency regressions, coverage drops,
and newly surfaced runtime errors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Optional


@dataclass
class Baseline:
    target: str
    duration_seconds: float = 0.0
    finding_counts: dict = field(default_factory=dict)
    endpoints_covered: int = 0
    p95_latency_ms: float = 0.0
    error_count: int = 0
    runs: int = 1

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "duration_seconds": self.duration_seconds,
            "finding_counts": self.finding_counts,
            "endpoints_covered": self.endpoints_covered,
            "p95_latency_ms": self.p95_latency_ms,
            "error_count": self.error_count,
            "runs": self.runs,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Baseline":
        return cls(**d)


@dataclass
class RegressionReport:
    target: str
    previous: Optional[Baseline]
    current: Baseline
    new_findings: list = field(default_factory=list)
    latency_regression_pct: float = 0.0
    coverage_dropped: bool = False
    error_increase: int = 0
    flags: list = field(default_factory=list)

    @property
    def has_regression(self) -> bool:
        return bool(self.flags)


class RegressionStore:
    def __init__(self, root: Path | str = ".remy/medusa/baselines") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(target: str) -> str:
        return sha256(target.encode()).hexdigest()[:16]

    def load(self, target: str) -> Optional[Baseline]:
        path = self.root / f"{self._key(target)}.json"
        if not path.exists():
            return None
        try:
            return Baseline.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return None

    def save(self, baseline: Baseline) -> None:
        path = self.root / f"{self._key(baseline.target)}.json"
        path.write_text(json.dumps(baseline.to_dict(), indent=2), encoding="utf-8")

    def compare(self, current: Baseline, new_findings: list) -> RegressionReport:
        prev = self.load(current.target)
        report = RegressionReport(target=current.target, previous=prev, current=current, new_findings=new_findings)

        if prev is None:
            report.flags.append("baseline-created")
            return report

        # new findings of any severity not present before
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            before = prev.finding_counts.get(sev, 0)
            after = current.finding_counts.get(sev, 0)
            if after > before:
                report.flags.append(f"new-{sev.lower()}-findings:+{after - before}")

        # latency regression (> 25%)
        if prev.p95_latency_ms > 0:
            pct = (current.p95_latency_ms - prev.p95_latency_ms) / prev.p95_latency_ms * 100
            report.latency_regression_pct = round(pct, 1)
            if pct >= 25:
                report.flags.append(f"latency-regression:+{report.latency_regression_pct}%")

        # coverage drop
        if current.endpoints_covered < prev.endpoints_covered:
            report.coverage_dropped = True
            report.flags.append(f"coverage-drop:{prev.endpoints_covered}->{current.endpoints_covered}")

        # error increase
        report.error_increase = current.error_count - prev.error_count
        if report.error_increase > 0:
            report.flags.append(f"error-increase:+{report.error_increase}")

        return report
