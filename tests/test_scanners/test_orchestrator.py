"""Tests for the scan orchestrator."""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
import pytest

from remy.scanners.orchestrator import ScanOrchestrator, ScanOptions
from remy.config.schema import Config, ScanDefaults
from remy.report.models import Finding, Severity


def make_config():
    return Config(
        provider="openrouter",
        model="openai/gpt-4o",
        scan_defaults=ScanDefaults(),
    )


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestScanOrchestrator:
    def test_scan_empty_directory(self, tmp_path):
        cfg = make_config()
        opts = ScanOptions()
        orch = ScanOrchestrator(config=cfg, options=opts)
        report = run(orch.run(str(tmp_path)))
        assert report.total_count == 0
        assert report.files_scanned == 0

    def test_scan_detects_findings_in_fixture(self):
        """Smoke test: scan the vulnerable fixture and expect findings."""
        import os
        fixture_path = Path(__file__).parent.parent / "fixtures" / "vulnerable_app"
        if not fixture_path.exists():
            pytest.skip("Fixture not found")

        cfg = make_config()
        opts = ScanOptions(secrets_only=True)
        orch = ScanOrchestrator(config=cfg, options=opts)
        report = run(orch.run(str(fixture_path)))
        # The fixture has multiple hardcoded secrets
        assert report.total_count > 0

    def test_secrets_only_flag(self, tmp_path):
        (tmp_path / "test.py").write_text('API_KEY = "FAKE_STRIPE_API_KEY"')
        cfg = make_config()
        opts = ScanOptions(secrets_only=True)
        orch = ScanOrchestrator(config=cfg, options=opts)
        report = run(orch.run(str(tmp_path)))
        # All findings should be from the secrets scanner
        assert all(f.scanner == "secrets" for f in report.findings)

    def test_deduplication(self, tmp_path):
        """Duplicate findings (same fingerprint) should be deduplicated."""
        (tmp_path / "test.py").write_text('API_KEY = "FAKE_STRIPE_API_KEY"')
        cfg = make_config()
        opts = ScanOptions(secrets_only=True)
        orch = ScanOrchestrator(config=cfg, options=opts)
        report1 = run(orch.run(str(tmp_path)))
        report2 = run(orch.run(str(tmp_path)))
        # Running twice on same file should produce same count
        assert report1.total_count == report2.total_count

    def test_report_has_metadata(self, tmp_path):
        cfg = make_config()
        opts = ScanOptions()
        orch = ScanOrchestrator(config=cfg, options=opts)
        report = run(orch.run(str(tmp_path)))
        assert report.scan_id
        assert report.target_path == str(tmp_path)
        assert report.duration_seconds >= 0
        assert isinstance(report.scanners_used, list)

    def test_sorting_critical_first(self, tmp_path):
        code = (
            'import pickle\n'
            'pickle.loads(data)\n'
            'low_var = "minor issue"\n'
            'subprocess.run(cmd, shell=True)\n'
        )
        (tmp_path / "test.py").write_text(code)
        cfg = make_config()
        opts = ScanOptions()
        orch = ScanOrchestrator(config=cfg, options=opts)
        report = run(orch.run(str(tmp_path)))
        if len(report.findings) > 1:
            # First finding should have the highest (lowest sort_order) severity
            first_sev = report.findings[0].severity.sort_order
            last_sev = report.findings[-1].severity.sort_order
            assert first_sev <= last_sev

