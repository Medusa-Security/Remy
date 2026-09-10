"""
JSON Export Module

Serializes a ScanReport to a machine-readable JSON string suitable for
piping into other tools, storing as CI artifacts, or feeding into
downstream processing pipelines.
"""

import json

from .models import ScanReport, Finding


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


def export_sarif(report: ScanReport, indent: int = 2) -> str:
    """Serialize a ScanReport to SARIF v2.1.0 format."""
    rules = {}
    results = []

    for f in report.sorted_findings():
        rule_id = (
            f.cwe
            if f.cwe and f.cwe != "CWE-Unknown"
            else f"{f.scanner}:{f.title.split()[0]}"
        )
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {
                    "text": f"{f.description}\n\nRemediation: {f.remediation_hint}"
                },
                "properties": {
                    "tags": [f.scanner, f.cwe] if f.cwe else [f.scanner],
                    "precision": "high" if f.confidence >= 0.8 else "medium",
                },
            }

        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        sarif_level = level_map.get(f.severity.value.lower(), "warning")

        results.append(
            {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {"text": f.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file.replace("\\", "/")},
                            "region": {
                                "startLine": max(1, f.line_start),
                                "endLine": max(1, f.line_end),
                                "snippet": (
                                    {"text": f.code_snippet} if f.code_snippet else {}
                                ),
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": round(f.confidence, 3),
                    "remediationHint": f.remediation_hint,
                    "remyId": f.id,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Remy",
                        "informationUri": "https://github.com/remy-security/remy",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=indent, ensure_ascii=False)


def export_gitlab_sast(report: ScanReport, indent: int = 2) -> str:
    """Serialize a ScanReport to GitLab SAST report format v15.x."""
    vulnerabilities = []
    for f in report.sorted_findings():
        gitlab_severity = f.severity.value.capitalize()
        if gitlab_severity not in ("Critical", "High", "Medium", "Low", "Info"):
            gitlab_severity = "Unknown"

        identifiers = [
            {
                "type": "remy_finding_id",
                "name": f.title,
                "value": f.id,
            }
        ]
        if f.cwe and f.cwe != "CWE-Unknown":
            cwe_id = f.cwe.upper().replace("CWE-", "")
            identifiers.append(
                {
                    "type": "cwe",
                    "name": f.cwe,
                    "value": cwe_id,
                    "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                }
            )

        vulnerabilities.append(
            {
                "id": f.id,
                "category": "sast",
                "name": f.title,
                "description": f.description,
                "severity": gitlab_severity,
                "confidence": (
                    "High"
                    if f.confidence >= 0.8
                    else ("Medium" if f.confidence >= 0.5 else "Low")
                ),
                "scanner": {"id": "remy", "name": "Remy Security Scanner"},
                "location": {
                    "file": f.file.replace("\\", "/"),
                    "start_line": max(1, f.line_start),
                    "end_line": max(1, f.line_end),
                },
                "identifiers": identifiers,
                "solution": f.remediation_hint,
            }
        )

    gitlab_data = {
        "version": "15.0.0",
        "vulnerabilities": vulnerabilities,
        "scan": {
            "analyzer": {
                "id": "remy",
                "name": "Remy Security Scanner",
                "vendor": {"name": "Remy Security"},
                "version": "1.0.0",
            },
            "scanner": {
                "id": "remy",
                "name": "Remy Security Scanner",
                "version": "1.0.0",
            },
            "type": "sast",
            "start_time": report.timestamp.isoformat(),
            "end_time": report.timestamp.isoformat(),
            "status": "success",
        },
    }
    return json.dumps(gitlab_data, indent=indent, ensure_ascii=False)
