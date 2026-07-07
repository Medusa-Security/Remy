"""
JSON Export Module

Serializes a ScanReport to a machine-readable JSON string suitable for
piping into other tools, storing as CI artifacts, or feeding into
downstream processing pipelines.
"""

import json
from datetime import datetime

from .models import ScanReport, Finding, Severity


def _finding_to_dict(finding: Finding) -> dict:
    """Convert a Finding dataclass to a JSON-serializable dict."""
    return {
        "id": finding.id,
        "scanner": finding.scanner,
        "severity": finding.severity.value,
        "cwe": finding.cwe,
        "file": finding.file,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "title": finding.title,
        "description": finding.description,
        "remediation_hint": finding.remediation_hint,
        "confidence": round(finding.confidence, 3),
        "code_snippet": finding.code_snippet,
    }


def export_json(report: ScanReport, indent: int = 2) -> str:
    """Serialize a ScanReport to a pretty-printed JSON string.

    The output structure is stable and suitable for machine consumption:

    {
      "scan_id": "...",
      "target_path": "...",
      "timestamp": "ISO-8601",
      "duration_seconds": 1.23,
      "files_scanned": 42,
      "scanners_used": [...],
      "summary": { "critical": 0, "high": 1, ... },
      "findings": [ { ... }, ... ]
    }

    Args:
        report: The ScanReport produced by the orchestrator.
        indent: JSON indentation level (default 2).

    Returns:
        JSON string representation of the report.
    """
    data = {
        "scan_id": report.scan_id,
        "target_path": str(report.target_path),
        "timestamp": report.timestamp.isoformat(),
        "duration_seconds": report.duration_seconds,
        "files_scanned": report.files_scanned,
        "scanners_used": report.scanners_used,
        "summary": {
            "total": report.total_count,
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "info": report.info_count,
        },
        "findings": [_finding_to_dict(f) for f in report.sorted_findings()],
    }

    return json.dumps(data, indent=indent, ensure_ascii=False)
