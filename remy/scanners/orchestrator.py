"""
Scan Orchestrator

Runs all enabled scanners concurrently, merges findings, deduplicates,
and assembles the final ScanReport with live progress display.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from remy.config.schema import Config
from remy.report.models import Finding, ScanReport
from remy.ui.progress import ScanProgress
from remy.utils.file_walker import FileWalker

from .base import Scanner
from .secrets_scanner import SecretsScanner
from .sast_python import PythonSastScanner
from .sast_js_ts import JsTsSastScanner
from .api_surface_scanner import ApiSurfaceScanner
from .auth_bypass_scanner import AuthBypassScanner
from .dependency_scanner import DependencyScanner


@dataclass
class ScanOptions:
    """Controls which scanners are enabled and scan parameters."""
    deep: bool = False               # Enable LLM logic-bug pass
    secrets_only: bool = False       # Only run secrets scanner
    api_surface_only: bool = False   # Only run API surface scanner
    bypass_check_only: bool = False  # Only run auth bypass scanner
    deps_only: bool = False          # Only run dependency scanner
    max_file_size_kb: int = 1000     # Maximum file size to scan
    respect_gitignore: bool = True   # Honor .gitignore / .remyignore
    min_severity: str = "INFO"       # Minimum severity to include in results


class ScanOrchestrator:
    """Coordinates all scanning engines and produces the final ScanReport."""

    def __init__(
        self,
        config: Config,
        options: ScanOptions,
        console: Optional[Console] = None,
    ) -> None:
        self.config = config
        self.options = options
        self.console = console or Console()

    def _select_scanners(self) -> list[Scanner]:
        """Instantiate and return the scanners enabled by options."""
        opts = self.options

        if opts.secrets_only:
            return [SecretsScanner()]
        if opts.api_surface_only:
            return [ApiSurfaceScanner()]
        if opts.bypass_check_only:
            return [AuthBypassScanner()]
        if opts.deps_only:
            return [DependencyScanner()]

        # Default: run all SAST scanners
        scanners: list[Scanner] = [
            SecretsScanner(),
            PythonSastScanner(),
            JsTsSastScanner(),
            ApiSurfaceScanner(),
            AuthBypassScanner(),
            DependencyScanner(),
        ]

        if opts.deep:
            # Lazy import to avoid circular dependency
            from remy.providers.registry import get_provider
            from .llm_logic_scanner import LlmLogicScanner
            try:
                provider = get_provider(self.config)
                scanners.append(LlmLogicScanner(provider))
            except Exception as e:
                self.console.print(
                    f"[yellow]⚠ LLM logic scanner disabled: {e}[/yellow]"
                )

        return scanners

    async def run(self, target_path: str) -> ScanReport:
        """Execute all enabled scanners and return the aggregated ScanReport.

        Process:
        1. Walk target directory to collect scannable files.
        2. Read file contents into memory.
        3. Select scanners based on options.
        4. Run all scanners concurrently per file.
        5. Merge, deduplicate, and sort findings.
        6. Build and return ScanReport.

        Args:
            target_path: Directory or file path to scan.

        Returns:
            ScanReport with all findings from all scanners.
        """
        start_time = time.perf_counter()
        scan_id = str(uuid.uuid4())[:8]

        # ── 1. Collect files ──────────────────────────────────────────────────
        walker = FileWalker(
            root=target_path,
            respect_gitignore=self.options.respect_gitignore,
            max_file_size_kb=self.options.max_file_size_kb,
        )
        file_paths = list(walker.walk())
        total_files = len(file_paths)

        if total_files == 0:
            self.console.print("[yellow]No scannable files found.[/yellow]")
            return ScanReport(
                scan_id=scan_id,
                target_path=target_path,
                timestamp=datetime.now(),
                findings=[],
                files_scanned=0,
                duration_seconds=0.0,
                scanners_used=[],
            )

        # ── 2. Read file contents ─────────────────────────────────────────────
        file_data: list[tuple[Path, str, str | None]] = []
        for p in file_paths:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                language = FileWalker.get_language(p)
                file_data.append((p, content, language))
            except OSError:
                continue

        # ── 3. Select scanners ────────────────────────────────────────────────
        scanners = self._select_scanners()
        scanner_names = [s.name for s in scanners]

        # ── 4. Run scanners concurrently with progress display ────────────────
        all_findings: list[Finding] = []

        async with ScanProgress(console=self.console) as progress:
            tasks_map: dict[int, str] = {}
            scanner_task_ids: dict[str, int] = {}

            for scanner in scanners:
                tid = progress.add_task(
                    f"[bold color(220)]{scanner.name.replace('_', ' ').title()}[/]",
                    total=len(file_data),
                )
                scanner_task_ids[scanner.name] = tid

            async def run_scanner(scanner: Scanner) -> list[Finding]:
                tid = scanner_task_ids[scanner.name]
                findings: list[Finding] = []
                for fp, content, language in file_data:
                    try:
                        file_findings = await scanner.scan_file(fp, content, language)
                        findings.extend(file_findings)
                    except Exception:
                        pass
                    progress.update(tid, advance=1)
                progress.complete(tid)
                return findings

            scanner_results = await asyncio.gather(
                *[run_scanner(s) for s in scanners],
                return_exceptions=True,
            )

        for result in scanner_results:
            if isinstance(result, list):
                all_findings.extend(result)

        # ── 5. Deduplicate by Finding.id ──────────────────────────────────────
        seen_ids: set[str] = set()
        unique_findings: list[Finding] = []
        for finding in all_findings:
            if finding.id not in seen_ids:
                seen_ids.add(finding.id)
                unique_findings.append(finding)

        # ── 5b. Apply minimum severity filter ─────────────────────────────────
        _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        _min_order = _sev_order.get(self.options.min_severity.upper(), 4)
        unique_findings = [
            f for f in unique_findings
            if f.severity.sort_order <= _min_order
        ]

        # ── 6. Sort: CRITICAL first, then by file, then by line ───────────────
        sorted_findings = sorted(
            unique_findings,
            key=lambda f: (f.severity.sort_order, f.file, f.line_start),
        )

        duration = time.perf_counter() - start_time

        return ScanReport(
            scan_id=scan_id,
            target_path=target_path,
            timestamp=datetime.now(),
            findings=sorted_findings,
            files_scanned=len(file_data),
            duration_seconds=round(duration, 2),
            scanners_used=scanner_names,
        )
