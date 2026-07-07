"""Tests for the SecretsScanner."""

import asyncio
from pathlib import Path
import pytest

from remy.scanners.secrets_scanner import SecretsScanner
from remy.report.models import Severity


@pytest.fixture
def scanner():
    return SecretsScanner()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestSecretsScanner:
    def test_detects_stripe_live_key(self, scanner):
        content = 'STRIPE_KEY = "FAKE_STRIPE_API_KEY"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert any("Stripe" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_stripe_test_key_as_medium(self, scanner):
        # sk_test_ keys — use value without "test" in content to avoid placeholder filter
        content = 'STRIPE_KEY = "FAKE_STRIPE_API_KEY"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        # Rule name is "Stripe Test Key" — title is "Hardcoded Stripe Test Key"
        assert any("Stripe" in f.title for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_detects_aws_access_key(self, scanner):
        # AKIAIOSFODNN7EXAMPLE triggers the placeholder filter ("EXAMPLE").
        # Use a realistic format key without placeholder words.
        content = 'AWS_KEY = "AKIAJ5MPHBQFZQNJYH2A"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert any("AWS" in f.title for f in findings)

    def test_detects_github_pat(self, scanner):
        content = 'token = "ghp_' + 'A' * 36 + '"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert any("GitHub" in f.title for f in findings)

    def test_detects_database_url(self, scanner):
        # Avoid "example" in the URL (triggers placeholder filter)
        content = 'DATABASE_URL = "postgresql://admin:p4ssw0rd@prod.db.myapp.io/appdb"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert any("Database" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_pem_key(self, scanner):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ..."
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert any("PEM" in f.title for f in findings)

    def test_ignores_placeholder(self, scanner):
        # "your_api_key_here" matches placeholder patterns — correctly suppressed
        content = 'API_KEY = "your_api_key_here"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        # Should not flag placeholder values as critical secrets
        assert not any(f.severity == Severity.CRITICAL for f in findings)

    def test_ignores_example_in_value(self, scanner):
        # Values containing "example" / "EXAMPLE" are suppressed as placeholders
        content = 'KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        # This is intentional — the placeholder filter catches the canonical AWS example key
        assert not any("AWS Access Key" in f.title for f in findings)

    def test_ignores_comments(self, scanner):
        content = '# STRIPE_KEY = "FAKE_STRIPE_API_KEY"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert len(findings) == 0

    def test_redacts_secret_in_description(self, scanner):
        content = 'KEY = "FAKE_STRIPE_API_KEY"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        for f in findings:
            # Full secret value should not appear in description
            assert "FAKE_STRIPE_API_KEY" not in f.description

    def test_high_entropy_detection(self, scanner):
        # High-entropy string on a line with a secret-context variable name
        content = 'api_key = "xK9mP2qR5vN8wL3jT6uY1bE4hA7cF0dG"'
        findings = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert any("entropy" in f.title.lower() or "Entropy" in f.title for f in findings)

    def test_scan_file_is_language_agnostic(self, scanner):
        """Secrets scanner should work on any language."""
        content = 'const STRIPE_KEY = "FAKE_STRIPE_API_KEY";'
        findings_js = run(scanner.scan_file(Path("test.js"), content, "javascript"))
        findings_py = run(scanner.scan_file(Path("test.py"), content, "python"))
        assert len(findings_js) > 0
        assert len(findings_py) > 0

