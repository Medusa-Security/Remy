from abc import ABC, abstractmethod
from pathlib import Path
import asyncio
from remy.report.models import Finding


class Scanner(ABC):
    """Abstract base class for all Remy scanning engines."""

    name: str = "base"

    @abstractmethod
    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Scan a single file and return a list of findings.

        Args:
            path: Absolute path to the file.
            content: Full text content of the file.
            language: Detected language name (e.g. 'python') or None.

        Returns:
            List of Finding objects for this file.
        """
        ...

    async def scan_files(
        self,
        files: list[tuple[Path, str, str | None]],
    ) -> list[Finding]:
        """Scan multiple files concurrently using asyncio.gather.

        Args:
            files: List of (path, content, language) tuples.

        Returns:
            Merged list of all findings across all files.
        """
        tasks = [self.scan_file(p, c, lang) for p, c, lang in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            # Silently swallow per-file scanner errors — they are logged elsewhere
        return findings
