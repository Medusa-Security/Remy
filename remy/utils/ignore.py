"""
False-Positive & Suppression Engine (.remyignore & inline comments)

Provides centralized suppression checking across all scanners:
1. .remyignore file specifications (by fingerprint hash, CWE, rule, or path glob).
2. Inline code comments on the finding line or the line immediately above:
   - `# remy:ignore` or `// remy:ignore`
   - `# nosec` or `// nosec`
   - Rule/CWE specific: `# remy:ignore CWE-798`
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from remy.report.models import Finding


@dataclass
class CweIgnoreRule:
    cwe: str
    path_pattern: Optional[str] = None


@dataclass
class SuppressionFilter:
    """Filters findings based on .remyignore and inline comment directives."""

    target_path: Path
    ignored_fingerprints: set[str] = field(default_factory=set)
    ignored_cwes: list[CweIgnoreRule] = field(default_factory=list)
    ignored_path_patterns: list[str] = field(default_factory=list)
    file_contents_cache: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def load(cls, target_path: str | Path) -> SuppressionFilter:
        """Load .remyignore from target_path if it exists."""
        root = Path(target_path).resolve()
        filter_instance = cls(target_path=root)
        ignore_file = root if root.is_file() else root / ".remyignore"
        if not ignore_file.is_file():
            return filter_instance

        try:
            lines = ignore_file.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines()
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # Check for ignore-fingerprint: <hash>
                if stripped.lower().startswith(("ignore-fingerprint:", "fingerprint:")):
                    parts = stripped.split(":", 1)
                    if len(parts) == 2:
                        filter_instance.ignored_fingerprints.add(parts[1].strip())
                    continue

                # Check for ignore-cwe: <cwe> [in <path-pattern>]
                if stripped.lower().startswith(("ignore-cwe:", "cwe:")):
                    parts = stripped.split(":", 1)[1].strip()
                    if " in " in parts.lower():
                        # Case insensitive split on ' in '
                        idx = parts.lower().index(" in ")
                        cwe = parts[:idx].strip().upper()
                        pat = parts[idx + 4 :].strip()
                        filter_instance.ignored_cwes.append(
                            CweIgnoreRule(cwe=cwe, path_pattern=pat)
                        )
                    else:
                        filter_instance.ignored_cwes.append(
                            CweIgnoreRule(cwe=parts.upper(), path_pattern=None)
                        )
                    continue

                # Otherwise treat as path glob pattern
                filter_instance.ignored_path_patterns.append(stripped)
        except OSError:
            pass

        return filter_instance

    def register_file_content(self, file_path: str | Path, content: str) -> None:
        """Cache split lines of a file for fast inline comment checking."""
        self.file_contents_cache[str(Path(file_path).resolve())] = content.splitlines()

    def is_suppressed(self, finding: Finding) -> bool:
        """Check if a finding should be suppressed by .remyignore or inline comments."""
        # 1. Check exact fingerprint hash
        if finding.id in self.ignored_fingerprints:
            return True

        # 2. Check path glob patterns
        rel_path = finding.file
        try:
            rel_path = str(Path(finding.file).resolve().relative_to(self.target_path))
        except ValueError:
            pass
        rel_path_unix = rel_path.replace("\\", "/")

        for pat in self.ignored_path_patterns:
            if fnmatch.fnmatch(rel_path_unix, pat) or fnmatch.fnmatch(
                finding.file.replace("\\", "/"), pat
            ):
                return True

        # 3. Check CWE suppressions
        if finding.cwe:
            cwe_upper = finding.cwe.upper()
            for rule in self.ignored_cwes:
                if rule.cwe == cwe_upper:
                    if rule.path_pattern is None:
                        return True
                    if fnmatch.fnmatch(
                        rel_path_unix, rule.path_pattern
                    ) or fnmatch.fnmatch(
                        finding.file.replace("\\", "/"), rule.path_pattern
                    ):
                        return True

        # 4. Check inline code comments on the finding line or line above
        abs_file = str(Path(finding.file).resolve())
        lines = self.file_contents_cache.get(abs_file)
        if lines and 1 <= finding.line_start <= len(lines):
            # Check current line and previous line (if exists)
            lines_to_check = [lines[finding.line_start - 1]]
            if finding.line_start > 1:
                lines_to_check.append(lines[finding.line_start - 2])

            for line_text in lines_to_check:
                lower_text = line_text.lower()
                if any(marker in lower_text for marker in ("remy:ignore", "nosec")):
                    # Check if marker specifies a specific CWE or ID
                    if finding.cwe and finding.cwe.lower() in lower_text:
                        return True
                    if finding.id.lower() in lower_text:
                        return True
                    # If just general remy:ignore or nosec without specific ID, suppress
                    # Make sure it's not e.g. remy:ignore CWE-89 when our finding is CWE-78
                    if not re.search(
                        r"(?:remy:ignore|nosec)\s+(?:cwe-\d+|[a-z0-9_-]+)",
                        lower_text,
                        re.IGNORECASE,
                    ):
                        return True

        return False

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Return only non-suppressed findings."""
        return [f for f in findings if not self.is_suppressed(f)]
