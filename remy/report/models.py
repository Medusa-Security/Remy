from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


class Severity(Enum):
    """Security finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        """Return rich color markup string for this severity."""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim white",
        }
        return colors[self.value]

    @property
    def sort_order(self) -> int:
        """Return sort priority (lower = higher priority)."""
        orders = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return orders[self.value]

    @property
    def icon(self) -> str:
        """Return an emoji icon for this severity."""
        icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }
        return icons[self.value]


@dataclass
class Finding:
    """Represents a single security or bug finding from a scanner."""
    id: str                            # unique fingerprint hash for deduplication
    scanner: str                       # which scanner produced this finding
    severity: Severity
    cwe: Optional[str]                 # e.g. "CWE-89"
    file: str                          # relative or absolute file path
    line_start: int
    line_end: int
    title: str
    description: str
    remediation_hint: str
    confidence: float                  # 0.0-1.0 confidence score
    code_snippet: Optional[str] = None # the vulnerable code lines for display


@dataclass
class ScanReport:
    """Aggregated report from a complete scan run."""
    scan_id: str
    target_path: str
    timestamp: datetime
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    scanners_used: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    def findings_by_file(self) -> dict[str, list[Finding]]:
        """Group findings by their file path, ordered by severity within each group."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.file, []).append(finding)
        for file_findings in grouped.values():
            file_findings.sort(key=lambda f: f.severity.sort_order)
        return grouped

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by severity (CRITICAL first) then by file path."""
        return sorted(self.findings, key=lambda f: (f.severity.sort_order, f.file, f.line_start))
