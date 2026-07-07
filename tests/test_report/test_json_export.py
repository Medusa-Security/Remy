"""Tests for JSON export."""

import json
from datetime import datetime
import pytest

from remy.report.models import Finding, Severity, ScanReport
from remy.report.json_export import export_json
from remy.utils.hashing import fingerprint_finding


def make_report():
    finding = Finding(
        id=fingerprint_finding("src/app.py", 10, "Test", "test"),
        scanner="sast_python",
        severity=Severity.HIGH,
        cwe="CWE-89",
        file="src/app.py",
        line_start=10,
        line_end=12,
        title="SQL Injection",
        description="SQL injection via f-string",
        remediation_hint="Use parameterized queries",
        confidence=0.9,
        code_snippet="cursor.execute(f'SELECT * WHERE id={user_id}')",
    )
    return ScanReport(
        scan_id="abc123",
        target_path="/project",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        findings=[finding],
        files_scanned=5,
        duration_seconds=2.1,
        scanners_used=["sast_python"],
    )


class TestJsonExport:
    def test_export_is_valid_json(self):
        report = make_report()
        result = export_json(report)
        data = json.loads(result)  # Should not raise
        assert isinstance(data, dict)

    def test_export_contains_scan_id(self):
        report = make_report()
        data = json.loads(export_json(report))
        assert data["scan_id"] == "abc123"

    def test_export_contains_summary(self):
        report = make_report()
        data = json.loads(export_json(report))
        assert "summary" in data
        assert data["summary"]["total"] == 1
        assert data["summary"]["high"] == 1
        assert data["summary"]["critical"] == 0

    def test_export_contains_findings(self):
        report = make_report()
        data = json.loads(export_json(report))
        assert len(data["findings"]) == 1
        f = data["findings"][0]
        assert f["title"] == "SQL Injection"
        assert f["severity"] == "HIGH"
        assert f["cwe"] == "CWE-89"

    def test_export_finding_has_all_fields(self):
        report = make_report()
        data = json.loads(export_json(report))
        f = data["findings"][0]
        required = ["id", "scanner", "severity", "cwe", "file", "line_start",
                    "line_end", "title", "description", "remediation_hint", "confidence"]
        for field in required:
            assert field in f, f"Missing field: {field}"

    def test_empty_report_exports_cleanly(self):
        report = ScanReport(
            scan_id="empty",
            target_path="/project",
            timestamp=datetime(2026, 1, 1),
            findings=[],
            files_scanned=0,
            duration_seconds=0.1,
            scanners_used=[],
        )
        data = json.loads(export_json(report))
        assert data["findings"] == []
        assert data["summary"]["total"] == 0

