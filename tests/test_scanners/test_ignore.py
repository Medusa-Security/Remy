"""Tests for SuppressionFilter (.remyignore & inline comments)."""

from remy.utils.ignore import SuppressionFilter
from remy.report.models import Finding, Severity


def make_finding(fid="hash123", cwe="CWE-798", file="src/app.py", line=10):
    return Finding(
        id=fid,
        scanner="test",
        severity=Severity.HIGH,
        cwe=cwe,
        file=file,
        line_start=line,
        line_end=line,
        title="Test finding",
        description="Test desc",
        remediation_hint="Fix it",
        confidence=0.9,
        code_snippet="api_key = 'sk_live_12345'",
    )


class TestSuppressionFilter:
    def test_ignore_by_fingerprint(self, tmp_path):
        ignore_file = tmp_path / ".remyignore"
        ignore_file.write_text("ignore-fingerprint: hash123\n", encoding="utf-8")
        f = SuppressionFilter.load(tmp_path)
        finding = make_finding(fid="hash123")
        assert f.is_suppressed(finding)

    def test_ignore_by_cwe(self, tmp_path):
        ignore_file = tmp_path / ".remyignore"
        ignore_file.write_text("ignore-cwe: CWE-798\n", encoding="utf-8")
        f = SuppressionFilter.load(tmp_path)
        finding = make_finding(cwe="CWE-798")
        assert f.is_suppressed(finding)

    def test_ignore_by_cwe_in_path(self, tmp_path):
        ignore_file = tmp_path / ".remyignore"
        ignore_file.write_text("ignore-cwe: CWE-798 in tests/*\n", encoding="utf-8")
        f = SuppressionFilter.load(tmp_path)
        finding1 = make_finding(cwe="CWE-798", file=str(tmp_path / "tests/test_app.py"))
        finding2 = make_finding(cwe="CWE-798", file=str(tmp_path / "src/app.py"))
        assert f.is_suppressed(finding1)
        assert not f.is_suppressed(finding2)

    def test_ignore_by_inline_comment_same_line(self, tmp_path):
        f = SuppressionFilter.load(tmp_path)
        file_path = tmp_path / "app.py"
        content = "api_key = '123'  # remy:ignore"
        f.register_file_content(file_path, content)
        finding = make_finding(file=str(file_path), line=1)
        assert f.is_suppressed(finding)

    def test_ignore_by_inline_comment_previous_line(self, tmp_path):
        f = SuppressionFilter.load(tmp_path)
        file_path = tmp_path / "app.py"
        content = "# nosec\napi_key = '123'"
        f.register_file_content(file_path, content)
        finding = make_finding(file=str(file_path), line=2)
        assert f.is_suppressed(finding)
