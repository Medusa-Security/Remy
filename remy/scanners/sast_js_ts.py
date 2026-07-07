"""
JavaScript / TypeScript SAST Scanner

Regex-based static analysis for JS/TS source files covering injection,
XSS, insecure crypto, prototype pollution, and more.

Rules are loaded from remy/rules/sast_rules/javascript_rules.yaml plus
a set of built-in high-confidence patterns defined in this module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from remy.report.models import Finding, Severity
from remy.utils.hashing import fingerprint_finding
from .base import Scanner

# Lines with nosec markers are skipped
NOSEC_MARKERS = ("# nosec", "// nosec", "// remy: nosec")


class _Rule(NamedTuple):
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    cwe: str
    remediation: str
    confidence: float = 0.80


BUILTIN_RULES: list[_Rule] = [
    _Rule(
        id="JS001",
        name="eval() with Dynamic Argument",
        pattern=re.compile(r"\beval\s*\(\s*(?!['\"`])"),
        severity=Severity.HIGH,
        cwe="CWE-78",
        remediation="Never use eval() with dynamic or user-supplied input. Use JSON.parse() for data or a safe template engine.",
        confidence=0.85,
    ),
    _Rule(
        id="JS002",
        name="child_process.exec with String Concatenation",
        pattern=re.compile(r"child_process\.exec\s*\(\s*[^,)\n]*\+"),
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        remediation="Use child_process.execFile() with an explicit argument array. Never concatenate user input into shell commands.",
        confidence=0.90,
    ),
    _Rule(
        id="JS003",
        name="innerHTML Assignment (XSS Risk)",
        pattern=re.compile(r"\.innerHTML\s*[+]?=(?!=)"),
        severity=Severity.HIGH,
        cwe="CWE-79",
        remediation="Use textContent/innerText for plain text. For HTML, sanitize with DOMPurify before assigning to innerHTML.",
        confidence=0.80,
    ),
    _Rule(
        id="JS004",
        name="document.write() Usage (XSS Risk)",
        pattern=re.compile(r"document\.write\s*\("),
        severity=Severity.MEDIUM,
        cwe="CWE-79",
        remediation="Avoid document.write(). Use DOM manipulation APIs or a templating library instead.",
        confidence=0.75,
    ),
    _Rule(
        id="JS005",
        name="Prototype Pollution Pattern",
        pattern=re.compile(r"__proto__\s*[\[.]|constructor\s*\.\s*prototype\s*[\[.]"),
        severity=Severity.HIGH,
        cwe="CWE-1321",
        remediation="Validate keys with Object.prototype.hasOwnProperty.call(). Use Object.create(null) for safe maps. Block '__proto__' keys at input boundaries.",
        confidence=0.85,
    ),
    _Rule(
        id="JS006",
        name="Hardcoded Secret in JS/TS Source",
        pattern=re.compile(
            r"(?:apiKey|api_key|apiSecret|secret|password|token|authToken)\s*[:=]\s*['\"`][A-Za-z0-9+/=_\-]{16,}['\"`]",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-798",
        remediation="Move to environment variable: process.env.SECRET_NAME. Use dotenv for local dev. Never commit .env files.",
        confidence=0.80,
    ),
    _Rule(
        id="JS007",
        name="Math.random() Used for Security Token",
        pattern=re.compile(r"Math\.random\s*\(\s*\)"),
        severity=Severity.MEDIUM,
        cwe="CWE-338",
        remediation="Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive random values.",
        confidence=0.65,
    ),
    _Rule(
        id="JS008",
        name="SQL Injection via Template Literal",
        pattern=re.compile(r"\.query\s*\(\s*`[^`]*\$\{"),
        severity=Severity.HIGH,
        cwe="CWE-89",
        remediation="Use parameterized queries or a query builder. Never interpolate variables into SQL strings.",
        confidence=0.90,
    ),
    _Rule(
        id="JS009",
        name="SSL Certificate Verification Disabled",
        pattern=re.compile(r"rejectUnauthorized\s*:\s*false"),
        severity=Severity.HIGH,
        cwe="CWE-295",
        remediation="Remove rejectUnauthorized: false. This disables TLS cert validation and enables MITM attacks.",
        confidence=0.95,
    ),
    _Rule(
        id="JS010",
        name="Dangerous dangerouslySetInnerHTML (React XSS)",
        pattern=re.compile(r"dangerouslySetInnerHTML\s*=\s*\{"),
        severity=Severity.HIGH,
        cwe="CWE-79",
        remediation="Only use dangerouslySetInnerHTML with sanitized content (DOMPurify). Never with user-supplied data.",
        confidence=0.85,
    ),
    _Rule(
        id="JS011",
        name="open() Redirect via User-Controlled URL",
        pattern=re.compile(
            r"(?:window\.location|res\.redirect|router\.push)\s*\(\s*req\.",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-601",
        remediation="Validate redirect URLs against an allowlist. Never redirect to a user-controlled URL directly.",
        confidence=0.75,
    ),
    _Rule(
        id="JS012",
        name="Insecure Deserialization via node-serialize",
        pattern=re.compile(r"serialize\.unserialize\s*\("),
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        remediation="Never use node-serialize or similar libraries with untrusted input. Use JSON.parse() instead.",
        confidence=0.95,
    ),
    _Rule(
        id="JS013",
        name="JWT Signed with Weak Algorithm (none/HS256 with hardcoded secret)",
        pattern=re.compile(
            r"jwt\.sign\s*\([^)]*,\s*['\"][^'\"]{1,20}['\"]",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        cwe="CWE-347",
        remediation="Use RS256 or ES256 with a proper key pair. If using HS256, load the secret from environment variables.",
        confidence=0.70,
    ),
    _Rule(
        id="JS014",
        name="Missing helmet() Security Headers (Express)",
        pattern=re.compile(
            r"const\s+app\s*=\s*express\s*\(\s*\)",
            re.IGNORECASE,
        ),
        severity=Severity.LOW,
        cwe="CWE-693",
        remediation="Add `app.use(helmet())` immediately after creating your Express app to set security headers.",
        confidence=0.50,
    ),
    _Rule(
        id="JS015",
        name="Insecure Random via Math for Security Use",
        pattern=re.compile(
            r"(?:token|session|nonce|secret|csrf)\s*[=+]=?\s*.*Math\.random",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        cwe="CWE-338",
        remediation="Use crypto.randomBytes(32).toString('hex') for security tokens.",
        confidence=0.85,
    ),
]


def _load_yaml_rules() -> list[_Rule]:
    """Load additional rules from javascript_rules.yaml."""
    try:
        import yaml
        rules_path = Path(__file__).parent.parent / "rules" / "sast_rules" / "javascript_rules.yaml"
        if not rules_path.exists():
            return []
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        sev_map = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO,
        }
        result = []
        for rule in data.get("rules", []):
            try:
                result.append(_Rule(
                    id=rule.get("id", "JS_YAML"),
                    name=rule["name"],
                    pattern=re.compile(rule["pattern"]),
                    severity=sev_map.get(rule.get("severity", "HIGH"), Severity.HIGH),
                    cwe=rule.get("cwe", "CWE-0"),
                    remediation=rule.get("remediation", "Review and fix the flagged pattern."),
                    confidence=0.75,
                ))
            except (re.error, KeyError):
                continue
        return result
    except Exception:
        return []


_YAML_RULES = _load_yaml_rules()
_ALL_RULES = BUILTIN_RULES + _YAML_RULES

JS_LANGS = {"javascript", "typescript"}
JS_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}


class JsTsSastScanner(Scanner):
    """Regex-based SAST scanner for JavaScript and TypeScript files."""

    name = "sast_js_ts"

    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Run all JS/TS rules against the file.

        Args:
            path: File path.
            content: Source code string.
            language: Detected language — must be javascript or typescript.

        Returns:
            List of findings. Empty for non-JS/TS files.
        """
        if language not in JS_LANGS and path.suffix.lower() not in JS_EXTS:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        seen_ids: set[str] = set()

        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1
            stripped = line.strip()

            # Skip blank lines, pure comments, and nosec annotations
            if not stripped:
                continue
            if stripped.startswith(("//", "*", "/*", "<!--")):
                continue
            if any(marker in line for marker in NOSEC_MARKERS):
                continue

            for rule in _ALL_RULES:
                if not rule.pattern.search(line):
                    continue

                fid = fingerprint_finding(str(path), line_no, rule.name, self.name)
                if fid in seen_ids:
                    continue
                seen_ids.add(fid)

                findings.append(
                    Finding(
                        id=fid,
                        scanner=self.name,
                        severity=rule.severity,
                        cwe=rule.cwe,
                        file=str(path),
                        line_start=line_no,
                        line_end=line_no,
                        title=f"[{rule.id}] {rule.name}",
                        description=(
                            f"{rule.name} detected at line {line_no}. "
                            f"Rule {rule.id} ({rule.cwe})."
                        ),
                        remediation_hint=rule.remediation,
                        confidence=rule.confidence,
                        code_snippet=line.rstrip(),
                    )
                )

        return findings
