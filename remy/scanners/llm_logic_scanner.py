"""
LLM Logic-Bug Scanner

Sends source code to the configured LLM provider with a structured
system prompt to detect logic errors, race conditions, edge cases,
and business logic flaws that static analysis cannot catch.
"""

import json
import re
from pathlib import Path
from remy.providers.base import Provider, Message
from remy.report.models import Finding, Severity
from remy.utils.hashing import fingerprint_finding
from .base import Scanner


SYSTEM_PROMPT = """\
You are a security-focused code reviewer with deep expertise in application security.
Analyze the provided code and identify:
- Logic errors and unhandled edge cases
- Race conditions and TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities
- Off-by-one errors in security-critical loops or conditions
- Null/undefined reference risks that could cause information leakage
- Unhandled exception paths that expose sensitive information
- Business logic flaws (e.g. negative quantities, integer overflow, price manipulation)
- Missing input validation or improper sanitization
- Concurrency bugs (shared state without locks)

Respond ONLY with a valid JSON array. Each item must have exactly these fields:
{
  "file": "<filename>",
  "line_start": <integer>,
  "line_end": <integer>,
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "cwe": "<CWE-XXX or null>",
  "title": "<concise bug title>",
  "description": "<clear description of the vulnerability or bug>",
  "remediation_hint": "<specific fix guidance>",
  "confidence": <0.0 to 1.0>
}

If you find no issues, return exactly: []
Never return anything other than the JSON array. No markdown, no prose.
"""

MAX_FILE_CHARS = 8000  # ~2000 tokens — keep within reasonable LLM context

# Languages we don't want to send to LLM (config, data, etc.)
SKIP_LANGUAGES = {"yaml", "json", "toml", "markdown", None}

# Map severity strings from LLM to Severity enum
SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class LlmLogicScanner(Scanner):
    """LLM-powered logic bug detector for deep code analysis."""

    name = "llm_logic"

    def __init__(self, provider: Provider) -> None:
        """Initialize with a configured provider.

        Args:
            provider: Any Provider implementation (OpenAI, Anthropic, Groq, etc.)
        """
        self.provider = provider

    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Send the file to the LLM for logic bug analysis.

        Args:
            path: File path (used as context for the LLM).
            content: File content (truncated if too long).
            language: Detected language.

        Returns:
            List of findings parsed from the LLM's JSON response.
        """
        if language in SKIP_LANGUAGES:
            return []

        # Truncate large files to stay within context limits
        if len(content) > MAX_FILE_CHARS:
            content = (
                content[:MAX_FILE_CHARS] + "\n\n# ... [file truncated by Remy] ..."
            )

        user_message = f"File: {path.name}\n\n```{language or ''}\n{content}\n```"

        messages = [
            Message(role="system", content=SYSTEM_PROMPT),
            Message(role="user", content=user_message),
        ]

        try:
            response = await self.provider.complete(
                messages,
                temperature=0.1,  # low temperature for consistent, analytical output
                max_tokens=2048,
            )
        except Exception:
            # Silently skip LLM failures per-file — don't crash the whole scan
            return []

        return self._parse_response(response, path)

    def _parse_response(self, response: str, path: Path) -> list[Finding]:
        """Parse the LLM JSON response into Finding objects.

        Handles common LLM response quirks (markdown code blocks, trailing text).

        Args:
            response: Raw LLM response string.
            path: File path for context.

        Returns:
            List of Finding objects parsed from the response.
        """
        findings: list[Finding] = []

        # Strip markdown code fences if the LLM wrapped the JSON
        cleaned = response.strip()
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r"```\s*$", "", cleaned, flags=re.MULTILINE).strip()

        # Extract the JSON array if there's extra text around it
        json_match = re.search(r"\[\s*(?:\{.*?\}\s*,?\s*)*\]", cleaned, re.DOTALL)
        if json_match:
            cleaned = json_match.group(0)

        try:
            items = json.loads(cleaned)
        except json.JSONDecodeError:
            return []

        if not isinstance(items, list):
            return []

        for item in items:
            if not isinstance(item, dict):
                continue

            severity_str = str(item.get("severity", "MEDIUM")).upper()
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            line_start = int(item.get("line_start", 1))
            line_end = int(item.get("line_end", line_start))
            title = str(item.get("title", "Logic Bug Detected"))
            description = str(item.get("description", ""))
            remediation = str(item.get("remediation_hint", ""))
            cwe = item.get("cwe") or None
            confidence = float(item.get("confidence", 0.70))

            fid = fingerprint_finding(str(path), line_start, title, self.name)
            findings.append(
                Finding(
                    id=fid,
                    scanner=self.name,
                    severity=severity,
                    cwe=cwe,
                    file=str(path),
                    line_start=line_start,
                    line_end=line_end,
                    title=title,
                    description=description,
                    remediation_hint=remediation,
                    confidence=confidence,
                    code_snippet=None,  # LLM doesn't return snippets
                )
            )

        return findings
