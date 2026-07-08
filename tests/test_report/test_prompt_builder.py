"""Tests for the Fix Prompt builder."""

from datetime import datetime
from pathlib import Path
import pytest

from remy.report.models import Finding, Severity, ScanReport
from remy.report.prompt_builder import build_fix_prompt, _redact_secret


def make_finding(
    severity=Severity.HIGH, file="src/app.py", line=10, title="Test Finding"
):
    from remy.utils.hashing import fingerprint_finding

    return Finding(
        id=fingerprint_finding(file, line, title, "test"),
        scanner="test",
        severity=severity,
        cwe="CWE-798",
        file=file,
        line_start=line,
        line_end=line,
        title=title,
        description="Test description",
        remediation_hint="Test remediation",
        confidence=0.9,
        code_snippet='API_KEY = "FAKE_STRIPE_API_KEY"',
    )


def make_report(findings=None):
    return ScanReport(
        scan_id="test123",
        target_path="/project",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        findings=findings or [],
        files_scanned=10,
        duration_seconds=1.5,
        scanners_used=["secrets", "sast_python"],
    )


class TestPromptBuilder:
    def test_empty_report_returns_empty_list(self):
        report = make_report(findings=[])
        result = build_fix_prompt(report)
        assert result == []

    def test_single_finding_returns_one_prompt(self):
        report = make_report(findings=[make_finding()])
        result = build_fix_prompt(report)
        assert len(result) == 1

    def test_prompt_contains_header(self):
        report = make_report(findings=[make_finding()])
        result = build_fix_prompt(report)
        assert "Remy Security & Bug Fix Prompt" in result[0]

    def test_prompt_contains_finding_title(self):
        finding = make_finding(title="Hardcoded Stripe Key")
        report = make_report(findings=[finding])
        result = build_fix_prompt(report)
        assert "Hardcoded Stripe Key" in result[0]

    def test_prompt_contains_file_path(self):
        finding = make_finding(file="src/payments.py")
        report = make_report(findings=[finding])
        result = build_fix_prompt(report)
        assert "src/payments.py" in result[0]

    def test_prompt_contains_severity_label(self):
        finding = make_finding(severity=Severity.CRITICAL)
        report = make_report(findings=[finding])
        result = build_fix_prompt(report)
        assert "CRITICAL" in result[0]

    def test_prompt_contains_verification_checklist(self):
        finding = make_finding()
        report = make_report(findings=[finding])
        result = build_fix_prompt(report)
        assert "Verification Checklist" in result[0]

    def test_prompt_contains_medusa_attribution(self):
        finding = make_finding()
        report = make_report(findings=[finding])
        result = build_fix_prompt(report)
        assert "Medusa Security" in result[0]

    def test_secret_redacted_in_code_snippet(self):
        finding = make_finding()
        # The code_snippet contains FAKE_STRIPE_API_KEY — should be redacted
        report = make_report(findings=[finding])
        result = build_fix_prompt(report)
        # Full value should not appear verbatim in the output
        assert "FAKE_STRIPE_API_KEY" not in result[0]

    def test_redact_secret_function(self):
        text = 'key = "FAKE_STRIPE_API_KEY"'
        redacted = _redact_secret(text)
        assert "sk_l" in redacted  # first 4 chars preserved
        assert "wxyz" in redacted  # last 4 chars preserved
        assert "abcdefghijklmnopqrstuv" not in redacted  # middle redacted

    def test_multiple_findings_grouped_by_file(self):
        f1 = make_finding(file="src/a.py", line=1, title="Bug A")
        f2 = make_finding(file="src/b.py", line=2, title="Bug B")
        f3 = make_finding(file="src/a.py", line=5, title="Bug C")
        report = make_report(findings=[f1, f2, f3])
        result = build_fix_prompt(report)
        content = result[0]
        # Both files should appear
        assert "src/a.py" in content
        assert "src/b.py" in content

    def test_chunking_on_large_reports(self):
        """Many findings should be chunked into multiple prompts."""
        findings = [
            make_finding(file=f"src/file{i}.py", line=i, title=f"Finding {i}" * 5)
            for i in range(200)
        ]
        report = make_report(findings=findings)
        result = build_fix_prompt(report)
        # Should produce multiple chunks
        assert len(result) > 1

    def test_chunked_prompts_have_part_numbers(self):
        findings = [
            make_finding(
                file=f"src/file{i}.py", line=i, title=f"Finding {'x' * 50} {i}"
            )
            for i in range(200)
        ]
        report = make_report(findings=findings)
        result = build_fix_prompt(report)
        if len(result) > 1:
            assert "Part 1" in result[0]
            assert "Part 2" in result[1]
