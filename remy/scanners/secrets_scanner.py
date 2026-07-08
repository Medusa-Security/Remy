"""
Secrets & Hardcoded Key Scanner

Detects hardcoded API keys, tokens, credentials, and high-entropy strings
in source code files using a combination of regex patterns and Shannon
entropy scoring.

Also loads additional patterns from remy/rules/secrets_patterns.yaml.
"""

import re
from pathlib import Path
from remy.report.models import Finding, Severity
from remy.utils.hashing import fingerprint_finding
from remy.utils.entropy import shannon_entropy
from .base import Scanner


# ── Load YAML rule extensions ─────────────────────────────────────────────────
def _load_yaml_rules() -> list[tuple[str, re.Pattern, Severity, str, str]]:
    """Load additional secret patterns from rules/secrets_patterns.yaml."""
    try:
        import yaml

        rules_path = Path(__file__).parent.parent / "rules" / "secrets_patterns.yaml"
        if not rules_path.exists():
            return []
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        result = []
        for rule in data.get("rules", []):
            try:
                compiled = re.compile(rule["pattern"])
                sev = sev_map.get(rule.get("severity", "HIGH"), Severity.HIGH)
                result.append(
                    (
                        rule["name"],
                        compiled,
                        sev,
                        rule.get("cwe", "CWE-798"),
                        rule.get(
                            "remediation",
                            "Move to environment variable or secret manager.",
                        ),
                    )
                )
            except (re.error, KeyError):
                continue
        return result
    except Exception:
        return []


# ── Placeholder patterns (false-positive suppression) ────────────────────────
# Note: sk_test_ keys are intentionally NOT suppressed — they are a real detection
# target (medium severity). The 'test' word match is scoped to avoid this.
PLACEHOLDER_PATTERNS = re.compile(
    r"(your[_\-]?key|your[_\-]?secret|your[_\-]?token|placeholder|replace[_\-]?me"
    r"|example|dummy|fake|xxx+|yyy+|zzz+|<[^>]+>|\$\{[^}]+\}"
    r"|sk-\.\.\.|INSERT|CHANGE_ME|MY_API_KEY|MY_SECRET"
    r"|\btest[_\-]?(?:key|secret|token|credential|password)\b"  # test_key etc, not sk_test_
    r"|test_value|testkey|testsecret)",
    re.IGNORECASE,
)


def _redact(value: str) -> str:
    """Redact the middle of a secret, showing only first 4 and last 4 chars."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "***" + value[-4:]


def _is_placeholder(value: str) -> bool:
    """Return True if the value looks like a placeholder, not a real secret."""
    return bool(PLACEHOLDER_PATTERNS.search(value))


# ── Regex rule definitions ────────────────────────────────────────────────────
# Each entry: (name, pattern, severity, cwe, remediation_hint)
SECRET_RULES: list[tuple[str, re.Pattern, Severity, str, str]] = [
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        Severity.CRITICAL,
        "CWE-798",
        "Remove from source code immediately. Store in AWS IAM / environment variables. Rotate the key via AWS IAM console.",
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r"(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['\"]?)([A-Za-z0-9/+]{40})(?:['\"]?)"
        ),
        Severity.CRITICAL,
        "CWE-798",
        "Rotate via AWS IAM. Store in AWS Secrets Manager or environment variable.",
    ),
    (
        "Stripe Live Key",
        re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
        Severity.CRITICAL,
        "CWE-798",
        "Revoke the key in Stripe Dashboard immediately. Use environment variables.",
    ),
    (
        "Stripe Test Key",
        re.compile(r"sk_test_[a-zA-Z0-9]{24,}"),
        Severity.MEDIUM,
        "CWE-798",
        "Remove test key from source. Even test keys can be abused. Use environment variables.",
    ),
    (
        "Slack Bot Token",
        re.compile(r"xoxb-[0-9]+-[0-9A-Za-z-]{6,}"),
        Severity.HIGH,
        "CWE-798",
        "Revoke token in Slack App settings. Store in environment variable or secret manager.",
    ),
    (
        "Slack App Token",
        re.compile(r"xoxa-[0-9]+-[0-9A-Za-z-]{6,}"),
        Severity.HIGH,
        "CWE-798",
        "Revoke in Slack App settings and store securely.",
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        Severity.CRITICAL,
        "CWE-798",
        "Revoke immediately at github.com/settings/tokens. Use GitHub Secrets for CI/CD.",
    ),
    (
        "GitHub OAuth Token",
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        Severity.CRITICAL,
        "CWE-798",
        "Revoke at github.com/settings/tokens. Use GitHub App auth instead.",
    ),
    (
        "GitHub Fine-Grained PAT",
        re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        Severity.CRITICAL,
        "CWE-798",
        "Revoke immediately. Store in GitHub Secrets or environment variable.",
    ),
    (
        "Generic API Key Assignment",
        re.compile(
            r"""(?:api[_\-]?key|apikey|api[_\-]?secret|client[_\-]?secret)\s*[=:]\s*['"][A-Za-z0-9+/=_\-]{16,}['"]""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-798",
        "Move to environment variable or secret manager. Never commit secrets.",
    ),
    (
        "Database Connection String with Credentials",
        re.compile(
            r"(?:postgres|postgresql|mysql|mongodb|redis|mssql|oracle)://[^:@\s]+:[^@\s]+@[^\s'\"]+"
        ),
        Severity.CRITICAL,
        "CWE-798",
        "Move database URL to environment variable. Use a secrets manager for production credentials.",
    ),
    (
        "PEM Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "CWE-321",
        "Remove private key from source code immediately. Generate a new key pair. Store keys in a secrets manager.",
    ),
    (
        "Generic Bearer Token in Code",
        re.compile(
            r"""(?:bearer|authorization)\s*[=:]\s*['"][A-Za-z0-9_.+/=-]{20,}['"]""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-798",
        "Move tokens to environment variables. Tokens in source code are a serious security risk.",
    ),
    (
        "Hardcoded JWT Token",
        re.compile(
            r"""['"]eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}['"]"""
        ),
        Severity.MEDIUM,
        "CWE-798",
        "Remove hardcoded JWT from source. Generate tokens at runtime and store signing secrets in environment variables.",
    ),
]


_YAML_RULES = _load_yaml_rules()


class SecretsScanner(Scanner):
    """Detects hardcoded secrets, API keys, and high-entropy credential strings.

    Merges built-in regex rules with patterns from rules/secrets_patterns.yaml
    and Shannon entropy analysis for novel key formats.
    """

    name = "secrets"
    ALL_RULES = SECRET_RULES + _YAML_RULES  # merged once at class definition time

    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Scan file content for secrets using regex rules and entropy analysis.

        Args:
            path: Path to the file being scanned.
            content: File content as string.
            language: Detected language (unused, scanner is language-agnostic).

        Returns:
            List of Finding objects for each secret detected.
        """
        findings: list[Finding] = []
        lines = content.splitlines()
        seen_ids: set[str] = set()

        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1
            stripped = line.strip()

            # Skip comments
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue

            # ── Rule-based detection ──────────────────────────────────────────
            for rule_name, pattern, severity, cwe, remediation in self.ALL_RULES:
                for match in pattern.finditer(line):
                    matched_value = match.group(0)
                    # Use the first capture group if available (e.g., for AWS secret)
                    if match.lastindex and match.lastindex >= 1:
                        matched_value = match.group(1)

                    if _is_placeholder(matched_value):
                        continue

                    fid = fingerprint_finding(str(path), line_no, rule_name, self.name)
                    if fid in seen_ids:
                        continue
                    seen_ids.add(fid)

                    redacted = _redact(matched_value)
                    findings.append(
                        Finding(
                            id=fid,
                            scanner=self.name,
                            severity=severity,
                            cwe=cwe,
                            file=str(path),
                            line_start=line_no,
                            line_end=line_no,
                            title=f"Hardcoded {rule_name}",
                            description=(
                                f"A {rule_name} was found hardcoded in source code: "
                                f"`{redacted}`. Committing secrets to version control "
                                f"is a critical security risk."
                            ),
                            remediation_hint=remediation,
                            confidence=0.90,
                            code_snippet=line.rstrip(),
                        )
                    )

        # ── High-entropy string detection ─────────────────────────────────────
        # Only flag high-entropy strings on lines that look like assignments to
        # secret-named variables, to reduce false positives on hashes/UUIDs/tokens.
        SECRET_VARNAME_RE = re.compile(
            r"(?:key|secret|token|password|passwd|credential|api[_\-]?key|auth|private)",
            re.IGNORECASE,
        )
        STRING_LITERAL_RE = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{20,100})['"]""")
        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1
            stripped_line = line.strip()
            if stripped_line.startswith(("#", "//", "*")):
                continue
            # Only check lines that have a secret-looking variable name nearby
            if not SECRET_VARNAME_RE.search(line):
                continue
            for match in STRING_LITERAL_RE.finditer(line):
                val = match.group(1)
                if _is_placeholder(val):
                    continue
                entropy = shannon_entropy(val)
                if entropy > 4.5:
                    fid = fingerprint_finding(
                        str(path), line_no, "high_entropy_string", self.name
                    )
                    if fid in seen_ids:
                        continue
                    seen_ids.add(fid)
                    findings.append(
                        Finding(
                            id=fid,
                            scanner=self.name,
                            severity=Severity.HIGH,
                            cwe="CWE-798",
                            file=str(path),
                            line_start=line_no,
                            line_end=line_no,
                            title="High-Entropy String Literal (Potential Secret)",
                            description=(
                                f"A high-entropy string literal was found: `{_redact(val)}` "
                                f"(entropy: {entropy:.2f} bits). This may be a hardcoded "
                                f"API key, token, or credential."
                            ),
                            remediation_hint=(
                                "Review this string. If it is a secret or credential, "
                                "move it to an environment variable or secret manager."
                            ),
                            confidence=0.65,
                            code_snippet=line.rstrip(),
                        )
                    )

        return findings
